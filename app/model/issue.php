<?php

namespace Model;

/**
 * Class Issue
 *
 * @property int $id
 * @property int $status
 * @property int $type_id
 * @property string $name
 * @property string $description
 * @property ?int $parent_id
 * @property int $author_id
 * @property ?int $owner_id
 * @property int $priority
 * @property ?float $hours_total
 * @property ?float $hours_remaining
 * @property ?float $hours_spent
 * @property string $created_date
 * @property ?string $closed_date
 * @property ?string $deleted_date
 * @property ?string $start_date
 * @property ?string $due_date
 * @property ?string $repeat_cycle
 * @property ?int $sprint_id
 *
 * @property ?int $update_comment ID of a comment attached to a pending update
 */
class Issue extends \Model
{
    protected $_table_name = 'issue';

    protected $_heirarchy;

    protected $_children;

    protected static $requiredFields = [
        'type_id',
        'status',
        'name',
        'author_id',
    ];

    /**
     * Fields accepted when creating an issue.
     *
     * This prevents unexpected request fields from being passed
     * directly to the ORM (mass assignment).
     */
    private const CREATE_FIELDS = [
        'status',
        'type_id',
        'name',
        'description',
        'parent_id',
        'author_id',
        'owner_id',
        'priority',
        'hours_total',
        'hours_remaining',
        'hours_spent',
        'created_date',
        'closed_date',
        'start_date',
        'due_date',
        'repeat_cycle',
        'sprint_id',
    ];

    private const REPEAT_CYCLES = [
        'daily',
        'weekly',
        'monthly',
        'quarterly',
        'semi_annually',
        'annually',
        'sprint',
    ];

    private const IMPORTANT_UPDATE_FIELDS = [
        'status',
        'name',
        'description',
        'owner_id',
        'priority',
        'due_date',
    ];

    /**
     * Maximum number of parents that may be traversed while
     * validating a hierarchy.
     */
    private const MAX_HIERARCHY_DEPTH = 1000;

    /**
     * Create and save a new issue.
     */
    public static function create(array $data, bool $notify = true): static
    {
        $data = self::normalizeCreateData($data);

        if (empty($data['author_id'])) {
            $userId = self::positiveInt(
                \Base::instance()->get('user.id')
            );

            if ($userId !== null) {
                $data['author_id'] = $userId;
            }
        }

        /** @var static $item */
        $item = parent::create($data);

        if (
            $notify
            && self::positiveInt($item->id) !== null
        ) {
            \Helper\Notification::instance()->issue_create(
                (int) $item->id
            );
        }

        return $item;
    }

    /**
     * Normalize and validate issue creation data.
     */
    private static function normalizeCreateData(array $data): array
    {
        /*
         * Convert the legacy "hours" field into the fields
         * actually persisted by the model.
         */
        if (array_key_exists('hours', $data)) {
            $hours = self::nullableNonNegativeFloat(
                $data['hours']
            );

            $data['hours_total'] = $hours;
            $data['hours_remaining'] = $hours;

            unset($data['hours']);
        }

        /*
         * Normalize textual fields.
         *
         * Description is intentionally not HTML-escaped here because
         * the application supports formatted text. Output escaping/XSS
         * filtering belongs to the rendering layer.
         */
        if (array_key_exists('name', $data)) {
            $data['name'] = self::sanitizeTitle(
                $data['name']
            );
        }

        if (array_key_exists('description', $data)) {
            $data['description'] = self::normalizeText(
                $data['description']
            );
        }

        /*
         * Normalize integer identifiers.
         */
        foreach (
            [
                'status',
                'type_id',
                'parent_id',
                'author_id',
                'owner_id',
                'sprint_id',
            ] as $field
        ) {
            if (!array_key_exists($field, $data)) {
                continue;
            }

            $data[$field] = self::positiveInt(
                $data[$field]
            );
        }

        if (array_key_exists('priority', $data)) {
            $priority = filter_var(
                $data['priority'],
                FILTER_VALIDATE_INT
            );

            $data['priority'] = $priority === false
                ? 0
                : $priority;
        }

        /*
         * Normalize numeric workload fields.
         */
        foreach (
            [
                'hours_total',
                'hours_remaining',
                'hours_spent',
            ] as $field
        ) {
            if (!array_key_exists($field, $data)) {
                continue;
            }

            $data[$field] = self::nullableNonNegativeFloat(
                $data[$field]
            );
        }

        /*
         * Normalize dates.
         */
        foreach (
            [
                'start_date',
                'due_date',
            ] as $field
        ) {
            if (!array_key_exists($field, $data)) {
                continue;
            }

            $data[$field] = self::normalizeDate(
                $data[$field]
            );
        }

        /*
         * Only supported repetition values may be persisted.
         */
        if (
            isset($data['repeat_cycle'])
            && !in_array(
                $data['repeat_cycle'],
                self::REPEAT_CYCLES,
                true
            )
        ) {
            $data['repeat_cycle'] = null;
        }

        /*
         * Automatically find the sprint containing the due date.
         */
        if (
            !empty($data['due_date'])
            && empty($data['sprint_id'])
            && !empty($data['due_date_sprint'])
        ) {
            $sprint = new Sprint();

            $sprint->load([
                'DATE(?) BETWEEN start_date AND end_date',
                $data['due_date'],
            ]);

            if ($sprint->id) {
                $data['sprint_id'] = (int) $sprint->id;
            }
        }

        /*
         * due_date_sprint controls application behavior and must
         * never be persisted as an Issue field.
         */
        unset($data['due_date_sprint']);

        /*
         * Explicit whitelist prevents mass assignment of
         * unexpected ORM properties.
         */
        return array_intersect_key(
            $data,
            array_flip(self::CREATE_FIELDS)
        );
    }

    /**
     * Get the complete parent list for an issue.
     */
    public function getAncestors(): array
    {
        if ($this->_heirarchy !== null) {
            return $this->_heirarchy;
        }

        $issues = [$this];
        $visitedIds = [];

        if ($this->id) {
            $visitedIds[(int) $this->id] = true;
        }

        $parentId = self::positiveInt(
            $this->parent_id
        );

        $depth = 0;

        while ($parentId !== null) {
            if (++$depth > self::MAX_HIERARCHY_DEPTH) {
                \Base::instance()->set(
                    'error',
                    'Issue parent hierarchy exceeds the allowed depth.'
                );

                break;
            }

            if (isset($visitedIds[$parentId])) {
                \Base::instance()->set(
                    'error',
                    sprintf(
                        'Issue parent tree contains an infinite loop at issue #%d.',
                        $parentId
                    )
                );

                break;
            }

            $visitedIds[$parentId] = true;

            $issue = new Issue();
            $issue->load($parentId);

            if (!$issue->id) {
                \Base::instance()->set(
                    'error',
                    sprintf(
                        'Issue parent tree references nonexistent issue #%d.',
                        $parentId
                    )
                );

                break;
            }

            $issues[] = $issue;

            $parentId = self::positiveInt(
                $issue->parent_id
            );
        }

        $this->_heirarchy = array_reverse(
            $issues
        );

        return $this->_heirarchy;
    }

    /**
     * Remove excessive whitespace from a string.
     */
    public static function clean(string $string): string
    {
        $string = str_replace(
            ["\r\n", "\r"],
            "\n",
            $string
        );

        return preg_replace(
            '/(?:\n\s*){2,}/',
            "\n\n",
            $string
        ) ?? $string;
    }

    /**
     * Soft-delete an issue.
     */
    public function delete(bool $recursive = true): Issue
    {
        if (!$this->deleted_date) {
            $this->set(
                'deleted_date',
                date('Y-m-d H:i:s')
            );
        }

        if ($recursive) {
            $this->_deleteTree();
        }

        return $this->save(false);
    }

    /**
     * Delete a complete issue tree.
     */
    protected function _deleteTree(): Issue
    {
        if (!$this->id) {
            return $this;
        }

        $children = $this->find([
            'parent_id = ?',
            $this->id,
        ]);

        foreach ($children as $child) {
            if (!$child instanceof Issue) {
                continue;
            }

            $child->delete();
        }

        return $this;
    }

    /**
     * Restore a deleted issue.
     */
    public function restore(bool $recursive = true): Issue
    {
        $this->set(
            'deleted_date',
            null
        );

        if ($recursive) {
            $this->_restoreTree();
        }

        return $this->save(false);
    }

    /**
     * Restore a complete issue tree.
     */
    protected function _restoreTree(): Issue
    {
        if (!$this->id) {
            return $this;
        }

        $children = $this->find([
            'parent_id = ? AND deleted_date IS NOT NULL',
            $this->id,
        ]);

        foreach ($children as $child) {
            if (!$child instanceof Issue) {
                continue;
            }

            $child->restore();
        }

        return $this;
    }

    /**
     * Repeat an issue by creating a minimal copy with a new due date.
     */
    public function repeat(bool $notify = true): Issue
    {
        $repeatIssue = $this->buildRepeatedIssue();

        $this->applyRepeatDates(
            $repeatIssue
        );

        $this->assignSprintToRepeatedIssue(
            $repeatIssue
        );

        $repeatIssue->save();

        if (
            $notify
            && $repeatIssue->id
        ) {
            \Helper\Notification::instance()->issue_create(
                (int) $repeatIssue->id
            );
        }

        return $repeatIssue;
    }

    /**
     * Build the base model for a repeated issue.
     */
    private function buildRepeatedIssue(): Issue
    {
        $repeatIssue = new Issue();

        $repeatIssue->name = self::sanitizeTitle(
            $this->name
        );

        $repeatIssue->type_id =
            $this->type_id;

        $repeatIssue->parent_id =
            $this->parent_id;

        $repeatIssue->author_id =
            $this->author_id;

        $repeatIssue->owner_id =
            $this->owner_id;

        $repeatIssue->description =
            $this->description;

        $repeatIssue->priority =
            $this->priority;

        $repeatIssue->repeat_cycle =
            $this->repeat_cycle;

        $repeatIssue->hours_total =
            $this->hours_total;

        $repeatIssue->hours_remaining =
            $this->hours_total;

        $repeatIssue->created_date =
            date('Y-m-d H:i:s');

        return $repeatIssue;
    }

    /**
     * Apply dates according to the repeat cycle.
     */
    private function applyRepeatDates(Issue $issue): void
    {
        switch ($issue->repeat_cycle) {
            case 'daily':
                $issue->start_date = $this->start_date
                    ? date('Y-m-d', strtotime('tomorrow'))
                    : null;

                $issue->due_date = date(
                    'Y-m-d',
                    strtotime('tomorrow')
                );
                break;

            case 'weekly':
                $issue->start_date = self::shiftDate(
                    $this->start_date,
                    '+1 week'
                );

                $issue->due_date = self::shiftDate(
                    $this->due_date,
                    '+1 week'
                );
                break;

            case 'monthly':
                $issue->start_date = self::shiftDate(
                    $this->start_date,
                    '+1 month'
                );

                $issue->due_date = self::shiftDate(
                    $this->due_date,
                    '+1 month'
                );
                break;

            case 'quarterly':
                $issue->start_date = self::shiftDate(
                    $this->start_date,
                    '+3 months'
                );

                $issue->due_date = self::shiftDate(
                    $this->due_date,
                    '+3 months'
                );
                break;

            case 'semi_annually':
                $issue->start_date = self::shiftDate(
                    $this->start_date,
                    '+6 months'
                );

                $issue->due_date = self::shiftDate(
                    $this->due_date,
                    '+6 months'
                );
                break;

            case 'annually':
                $issue->start_date = self::shiftDate(
                    $this->start_date,
                    '+1 year'
                );

                $issue->due_date = self::shiftDate(
                    $this->due_date,
                    '+1 year'
                );
                break;

            case 'sprint':
                $this->applyNextSprintDates(
                    $issue
                );
                break;

            default:
                $issue->repeat_cycle = null;
                break;
        }
    }

    /**
     * Apply dates from the next available sprint.
     */
    private function applyNextSprintDates(Issue $issue): void
    {
        $sprint = new Sprint();

        $sprint->load(
            ['start_date > NOW()'],
            ['order' => 'start_date']
        );

        if (!$sprint->id) {
            return;
        }

        $issue->start_date = $this->start_date
            ? $sprint->start_date
            : null;

        $issue->due_date =
            $sprint->end_date;
    }

    /**
     * Put the repeated issue into the sprint containing its due date.
     */
    private function assignSprintToRepeatedIssue(
        Issue $issue
    ): void {
        if (
            !$this->sprint_id
            || !$issue->due_date
        ) {
            return;
        }

        $sprint = new Sprint();

        $sprint->load(
            [
                'end_date >= ? AND start_date <= ?',
                $issue->due_date,
                $issue->due_date,
            ],
            [
                'order' => 'start_date',
            ]
        );

        if ($sprint->id) {
            $issue->sprint_id =
                (int) $sprint->id;
        }
    }

    /**
     * Log and save an issue update.
     *
     * @return Issue\Update|false
     */
    protected function _saveUpdate(
        bool $notify = true
    ): Issue\Update|false {
        $f3 = \Base::instance();

        $this->validateParentRelationship();

        $update = new Issue\Update();

        $update->issue_id =
            (int) $this->id;

        $update->user_id =
            self::positiveInt(
                $f3->get('user.id')
            );

        $update->created_date =
            date('Y-m-d H:i:s');

        $update->notify = 0;

        if ($f3->exists('update_comment')) {
            $comment = $f3->get(
                'update_comment'
            );

            if (
                is_object($comment)
                && !empty($comment->id)
            ) {
                $update->comment_id =
                    (int) $comment->id;

                $update->notify =
                    $notify ? 1 : 0;
            }
        }

        $update->save();

        $this->normalizeHoursAfterUpdate();

        $this->handleRepeatAfterClose(
            $notify
        );

        [
            $updatedFields,
            $importantChanges,
        ] = $this->logChangedFields(
            $update
        );

        if ($updatedFields === 0) {
            $update->delete();

            return false;
        }

        if (
            $notify
            && $importantChanges > 0
        ) {
            $update->notify = 1;
            $update->save();
        }

        return $update;
    }

    /**
     * Validate the parent relationship before persistence.
     */
    private function validateParentRelationship(): void
    {
        $parentId = self::positiveInt(
            $this->parent_id
        );

        if ($parentId === null) {
            $this->parent_id = null;
            return;
        }

        /*
         * An issue cannot reference itself.
         */
        if ((int) $this->id === $parentId) {
            $this->parent_id =
                $this->_getPrev('parent_id');

            return;
        }

        /*
         * Ensure the parent exists.
         */
        $parent = new Issue();
        $parent->load($parentId);

        if (!$parent->id) {
            $this->parent_id =
                $this->_getPrev('parent_id');

            return;
        }

        /*
         * Prevent assigning a descendant as the parent,
         * which would create a circular hierarchy.
         */
        if ($this->wouldCreateCircularHierarchy($parent)) {
            $this->parent_id =
                $this->_getPrev('parent_id');

            return;
        }

        $this->parent_id = $parentId;
    }

    /**
     * Determine whether assigning the supplied issue as parent
     * would introduce a hierarchy cycle.
     */
    private function wouldCreateCircularHierarchy(
        Issue $parent
    ): bool {
        if (!$this->id) {
            return false;
        }

        $currentId = self::positiveInt(
            $parent->id
        );

        $visited = [];
        $depth = 0;

        while ($currentId !== null) {
            if (++$depth > self::MAX_HIERARCHY_DEPTH) {
                return true;
            }

            if ($currentId === (int) $this->id) {
                return true;
            }

            if (isset($visited[$currentId])) {
                return true;
            }

            $visited[$currentId] = true;

            $current = new Issue();
            $current->load($currentId);

            if (!$current->id) {
                return false;
            }

            $currentId = self::positiveInt(
                $current->parent_id
            );
        }

        return false;
    }

    /**
     * Normalize hours after an update.
     */
    private function normalizeHoursAfterUpdate(): void
    {
        if (
            $this->hours_remaining
            && !$this->hours_total
            && !$this->_getPrev('hours_remaining')
            && !$this->_getPrev('hours_total')
        ) {
            $this->hours_total =
                $this->hours_remaining;
        }

        if (
            $this->closed_date
            && (float) $this->hours_remaining > 0
        ) {
            $this->hours_remaining = 0;
        }
    }

    /**
     * Generate the next issue when a repeating issue is closed.
     */
    private function handleRepeatAfterClose(
        bool $notify
    ): void {
        if (
            !$this->closed_date
            || !$this->repeat_cycle
        ) {
            return;
        }

        $this->repeat($notify);

        $this->repeat_cycle = null;
    }

    /**
     * Store changed fields in issue update history.
     *
     * @return array{0:int,1:int}
     */
    private function logChangedFields(
        Issue\Update $update
    ): array {
        $updatedCount = 0;
        $importantCount = 0;

        foreach ($this->fields as $key => $field) {
            if (
                empty($field['changed'])
            ) {
                continue;
            }

            $newValue =
                $field['value'] ?? null;

            $oldValue =
                $this->_getPrev($key);

            if (
                !$this->valuesDiffer(
                    $newValue,
                    $oldValue
                )
            ) {
                continue;
            }

            $updateField =
                new Issue\Update\Field();

            $updateField->issue_update_id =
                $update->id;

            $updateField->field =
                (string) $key;

            $updateField->old_value =
                $oldValue;

            $updateField->new_value =
                $newValue;

            $updateField->save();

            $updatedCount++;

            if ($key === 'sprint_id') {
                $this->resetTaskSprints();
            }

            if (
                in_array(
                    $key,
                    self::IMPORTANT_UPDATE_FIELDS,
                    true
                )
            ) {
                $importantCount++;
            }
        }

        return [
            $updatedCount,
            $importantCount,
        ];
    }

    /**
     * Compare values using their normalized string representation.
     */
    private function valuesDiffer(
        mixed $newValue,
        mixed $oldValue
    ): bool {
        return rtrim(
            (string) ($newValue ?? '')
        ) !== rtrim(
            (string) ($oldValue ?? '')
        );
    }

    /**
     * Save an issue and send applicable notifications.
     */
    public function save(bool $notify = true): Issue
    {
        $f3 = \Base::instance();

        $this->normalizeBeforeSave();

        if ($this->query) {
            $update =
                $this->_saveUpdate($notify);

            $issue =
                parent::save();

            if (
                $notify
                && $update instanceof Issue\Update
                && $update->id
                && $update->notify
            ) {
                \Helper\Notification::instance()
                    ->issue_update(
                        (int) $this->id,
                        (int) $update->id
                    );
            }
        } else {
            $this->setClosedDateFromStatus();

            $issue =
                parent::save();
        }

        $this->saveTags();

        return $issue;
    }

    /**
     * Normalize data immediately before persistence.
     */
    private function normalizeBeforeSave(): void
    {
        if (
            $this->sprint_id === 0
            || $this->sprint_id === '0'
        ) {
            $this->set(
                'sprint_id',
                null
            );
        }

        $this->name = self::sanitizeTitle(
            $this->name
        );

        $this->description = self::normalizeText(
            $this->description
        );

        $this->due_date =
            self::normalizeDate(
                $this->due_date
            );

        $this->start_date =
            self::normalizeDate(
                $this->start_date
            );

        $this->hours_total =
            self::nullableNonNegativeFloat(
                $this->hours_total
            );

        $this->hours_remaining =
            self::nullableNonNegativeFloat(
                $this->hours_remaining
            );

        $this->hours_spent =
            self::nullableNonNegativeFloat(
                $this->hours_spent
            );

        $this->normalizeRepeatCycle();

        $this->censorCreditCardNumbers();
    }

    /**
     * Censor credit-card-like strings when the option is enabled.
     */
    private function censorCreditCardNumbers(): void
    {
        $f3 = \Base::instance();

        if (
            !$f3->get('security.block_ccs')
        ) {
            return;
        }

        $description =
            (string) ($this->description ?? '');

        if ($description === '') {
            return;
        }

        /*
         * Preserve the original behavior while making the
         * grouping/precedence explicit.
         */
        $pattern =
            '/(?:\d{3,4}-){3}(\d{3,4})/';

        if (
            preg_match(
                $pattern,
                $description
            ) !== 1
        ) {
            return;
        }

        $filtered = preg_replace(
            $pattern,
            '************$1',
            $description
        );

        if ($filtered !== null) {
            $this->set(
                'description',
                $filtered
            );
        }
    }

    /**
     * Keep only supported repeat cycle values.
     */
    private function normalizeRepeatCycle(): void
    {
        if (
            !is_string($this->repeat_cycle)
            || !in_array(
                $this->repeat_cycle,
                self::REPEAT_CYCLES,
                true
            )
        ) {
            $this->repeat_cycle = null;
        }
    }

    /**
     * Set closed_date when creating an issue in a closed status.
     */
    private function setClosedDateFromStatus(): void
    {
        if (
            $this->closed_date
            || !$this->status
        ) {
            return;
        }

        $statusId = self::positiveInt(
            $this->status
        );

        if ($statusId === null) {
            return;
        }

        $status = new Issue\Status();

        $status->load($statusId);

        if (
            $status->id
            && $status->closed
        ) {
            $this->closed_date =
                date('Y-m-d H:i:s');
        }
    }

    /**
     * Find and save the current issue's tags.
     */
    public function saveTags(): Issue
    {
        $issueId = self::positiveInt(
            $this->id
        );

        if ($issueId === null) {
            return $this;
        }

        $tag = new Issue\Tag();

        $tag->deleteByIssueId(
            $issueId
        );

        if ($this->deleted_date) {
            return $this;
        }

        $description =
            (string) ($this->description ?? '');

        if ($description === '') {
            return $this;
        }

        $count = preg_match_all(
            '/(?:(?<=#)|(?<=[^a-z\/&]#))'
            . '[a-z][a-z0-9_-]*[a-z0-9]+'
            . '(?=[^a-z\/]|$)/i',
            $description,
            $matches
        );

        if (
            $count === false
            || $count === 0
        ) {
            return $this;
        }

        $saved = [];

        foreach ($matches[0] as $match) {
            $normalizedTag = preg_replace(
                '/[_-]+/',
                '-',
                ltrim(
                    (string) $match,
                    '#'
                )
            );

            if (
                !is_string($normalizedTag)
                || $normalizedTag === ''
                || isset($saved[$normalizedTag])
            ) {
                continue;
            }

            $tag->reset();

            $tag->tag =
                $normalizedTag;

            $tag->issue_id =
                $issueId;

            $tag->save();

            $saved[$normalizedTag] = true;
        }

        return $this;
    }

    /**
     * Duplicate an issue and optionally all descendants.
     *
     * @throws \Exception
     */
    public function duplicate(
        bool $recursive = true
    ): Issue {
        if (!$this->id) {
            throw new \Exception(
                'Cannot duplicate an issue that is not yet saved.'
            );
        }

        $newIssue =
            $this->duplicateCurrentIssue();

        if (
            $recursive
            && $newIssue->id
        ) {
            $this->_duplicateTree(
                (int) $this->id,
                (int) $newIssue->id
            );
        }

        return $newIssue;
    }

    /**
     * Duplicate the current issue.
     */
    private function duplicateCurrentIssue(): Issue
    {
        $f3 = \Base::instance();

        $this->copyto(
            'duplicating_issue'
        );

        $this->clearDuplicateTransientFields(
            $f3
        );

        $newIssue = new Issue();

        $newIssue->copyfrom(
            'duplicating_issue'
        );

        $newIssue->author_id =
            self::positiveInt(
                $f3->get('user.id')
            );

        $newIssue->hours_remaining =
            $newIssue->hours_total;

        $newIssue->created_date =
            date('Y-m-d H:i:s');

        $newIssue->save();

        return $newIssue;
    }

    /**
     * Clear properties that must not be copied to a duplicate.
     */
    private function clearDuplicateTransientFields(
        \Base $f3
    ): void {
        $f3->clear(
            'duplicating_issue.id'
        );

        $f3->clear(
            'duplicating_issue.due_date'
        );

        $f3->clear(
            'duplicating_issue.hours_spent'
        );

        $f3->clear(
            'duplicating_issue.closed_date'
        );

        $f3->clear(
            'duplicating_issue.deleted_date'
        );
    }

    /**
     * Duplicate a complete descendant tree.
     */
    protected function _duplicateTree(
        int $id,
        int $newId
    ): Issue {
        if (
            $id <= 0
            || $newId <= 0
        ) {
            return $this;
        }

        $children = $this->find([
            'parent_id = ?',
            $id,
        ]);

        foreach ($children as $child) {
            if (
                !$child instanceof Issue
                || $child->deleted_date
            ) {
                continue;
            }

            $newChild =
                $this->duplicateChildIssue(
                    $child,
                    $newId
                );

            if ($newChild->id) {
                $this->_duplicateTree(
                    (int) $child->id,
                    (int) $newChild->id
                );
            }
        }

        return $this;
    }

    /**
     * Duplicate a single child issue.
     */
    private function duplicateChildIssue(
        Issue $child,
        int $newParentId
    ): Issue {
        $f3 = \Base::instance();

        $child->copyto(
            'duplicating_issue'
        );

        $this->clearDuplicateTransientFields(
            $f3
        );

        $newChild = new Issue();

        $newChild->copyfrom(
            'duplicating_issue'
        );

        $newChild->author_id =
            self::positiveInt(
                $f3->get('user.id')
            );

        $newChild->hours_remaining =
            $newChild->hours_total;

        $newChild->parent_id =
            $newParentId;

        $newChild->created_date =
            date('Y-m-d H:i:s');

        $newChild->save(false);

        return $newChild;
    }

    /**
     * Move non-project children to the same sprint.
     */
    public function resetTaskSprints(
        bool $replaceExisting = true
    ): Issue {
        $sprintId = self::positiveInt(
            $this->sprint_id
        );

        $issueId = self::positiveInt(
            $this->id
        );

        if (
            $sprintId === null
            || $issueId === null
        ) {
            return $this;
        }

        $f3 = \Base::instance();

        $projectType = self::positiveInt(
            $f3->get('issue_type.project')
        );

        if ($projectType === null) {
            return $this;
        }

        $query =
            'UPDATE issue '
            . 'SET sprint_id = :sprint '
            . 'WHERE parent_id = :issue '
            . 'AND type_id != :type';

        /*
         * Preserve the existing application behavior.
         */
        if ($replaceExisting) {
            $query .=
                ' AND sprint_id IS NULL';
        }

        $this->db->exec(
            $query,
            [
                ':sprint' =>
                    $sprintId,

                ':issue' =>
                    $issueId,

                ':type' =>
                    $projectType,
            ]
        );

        return $this;
    }

    /**
     * Get direct children of this issue.
     */
    public function getChildren(): array
    {
        if ($this->_children !== null) {
            return $this->_children;
        }

        if (!$this->id) {
            $this->_children = [];

            return $this->_children;
        }

        $children = $this->find([
            'parent_id = ? AND deleted_date IS NULL',
            $this->id,
        ]);

        $this->_children =
            is_iterable($children)
                ? $children
                : [];

        return $this->_children;
    }

    /**
     * Generate hashes for each field used by the existing
     * client-side change-state mechanism.
     *
     * MD5 is retained here solely for protocol compatibility.
     * It must not be used for passwords, tokens or authentication.
     */
    public function hashState(): array
    {
        $result = $this->cast();

        foreach ($result as &$value) {
            $value = md5(
                (string) ($value ?? '')
            );
        }

        unset($value);

        return $result;
    }

    /**
     * Close the issue.
     */
    public function close(): Issue
    {
        if (
            !$this->id
            || $this->closed_date
        ) {
            return $this;
        }

        $status = new Issue\Status();

        $status->load([
            'closed = ?',
            1,
        ]);

        if (!$status->id) {
            return $this;
        }

        $this->status =
            (int) $status->id;

        $this->closed_date =
            date('Y-m-d H:i:s');

        $this->save();

        return $this;
    }

    /**
     * Get all descendant IDs, including the current issue ID.
     */
    public function descendantIds(): array
    {
        if (!$this->id) {
            return [];
        }

        $ids = [
            (int) $this->id,
        ];

        foreach ($this->getChildren() as $child) {
            if (!$child instanceof Issue) {
                continue;
            }

            $ids = array_merge(
                $ids,
                $child->descendantIds()
            );
        }

        return array_values(
            array_unique(
                array_map(
                    'intval',
                    $ids
                )
            )
        );
    }

    /**
     * Get aggregate statistics across the issue tree.
     */
    public function projectStats(): array
    {
        $result = [
            'total' => 0,
            'complete' => 0,
            'hours_spent' => 0.0,
            'hours_total' => 0.0,
        ];

        if (!$this->id) {
            return $result;
        }

        $result['total'] = 1;

        if ($this->closed_date) {
            $result['complete'] = 1;
        }

        $result['hours_spent'] =
            max(
                0.0,
                (float) ($this->hours_spent ?? 0)
            );

        $result['hours_total'] =
            max(
                0.0,
                (float) ($this->hours_total ?? 0)
            );

        foreach ($this->getChildren() as $child) {
            if (!$child instanceof Issue) {
                continue;
            }

            $childStats =
                $child->projectStats();

            $result['total'] +=
                (int) $childStats['total'];

            $result['complete'] +=
                (int) $childStats['complete'];

            $result['hours_spent'] +=
                (float) $childStats['hours_spent'];

            $result['hours_total'] +=
                (float) $childStats['hours_total'];
        }

        return $result;
    }

    /**
     * Check whether the current/given user may access this issue.
     */
    public function allowAccess(
        ?\Model\User $user = null
    ): bool {
        $f3 = \Base::instance();

        if (!$user instanceof \Model\User) {
            $userCandidate =
                $f3->get('user_obj');

            if (
                !$userCandidate instanceof
                \Model\User
            ) {
                /*
                 * Fail closed if no authenticated user model exists.
                 */
                return false;
            }

            $user = $userCandidate;
        }

        /*
         * Administrator retains unrestricted access,
         * preserving the original behavior.
         */
        if ($user->role === 'admin') {
            return true;
        }

        if ($this->deleted_date) {
            return false;
        }

        if (
            !$f3->get(
                'security.restrict_access'
            )
        ) {
            return true;
        }

        $userId = self::positiveInt(
            $user->id
        );

        if ($userId === null) {
            return false;
        }

        $ownerId = self::positiveInt(
            $this->owner_id
        );

        $authorId = self::positiveInt(
            $this->author_id
        );

        if (
            $ownerId === $userId
            || $authorId === $userId
        ) {
            return true;
        }

        $groupIds =
            \Helper\Dashboard::instance()
                ->getGroupIds();

        if (
            !is_array($groupIds)
            || $ownerId === null
        ) {
            return false;
        }

        $groupIds = array_map(
            'intval',
            $groupIds
        );

        return in_array(
            $ownerId,
            $groupIds,
            true
        );
    }

    /**
     * Sanitize the issue title.
     *
     * Control characters are removed while normal text,
     * accents and Unicode characters are preserved.
     */
    private static function sanitizeTitle(
        mixed $value
    ): string {
        if (!is_scalar($value)) {
            return '';
        }

        $value = trim(
            (string) $value
        );

        /*
         * Remove ASCII control characters except normal whitespace.
         */
        $value = preg_replace(
            '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u',
            '',
            $value
        );

        if ($value === null) {
            return '';
        }

        /*
         * Prevent excessively large values from reaching
         * persistence/logging layers.
         */
        if (
            function_exists('mb_substr')
        ) {
            return mb_substr(
                $value,
                0,
                255
            );
        }

        return substr(
            $value,
            0,
            255
        );
    }

    /**
     * Normalize free text without destroying Markdown/Textile markup.
     */
    private static function normalizeText(
        mixed $value
    ): string {
        if (!is_scalar($value)) {
            return '';
        }

        $value = (string) $value;

        $value = str_replace(
            ["\r\n", "\r"],
            "\n",
            $value
        );

        /*
         * Remove null bytes and unsafe ASCII control characters.
         */
        $value = str_replace(
            "\0",
            '',
            $value
        );

        return preg_replace(
            '/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/u',
            '',
            $value
        ) ?? '';
    }

    /**
     * Convert a value into a positive integer or null.
     */
    private static function positiveInt(
        mixed $value
    ): ?int {
        if (
            $value === null
            || $value === ''
        ) {
            return null;
        }

        $result = filter_var(
            $value,
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                ],
            ]
        );

        return $result === false
            ? null
            : $result;
    }

    /**
     * Convert optional numeric values into a non-negative float.
     */
    private static function nullableNonNegativeFloat(
        mixed $value
    ): ?float {
        if (
            $value === null
            || $value === ''
        ) {
            return null;
        }

        if (
            !is_numeric($value)
        ) {
            return null;
        }

        $value = (float) $value;

        if (
            !is_finite($value)
            || $value < 0
        ) {
            return null;
        }

        return $value;
    }

    /**
     * Normalize an input date to YYYY-MM-DD.
     */
    private static function normalizeDate(
        mixed $value
    ): ?string {
        if (
            $value === null
            || $value === ''
            || !is_scalar($value)
        ) {
            return null;
        }

        $value = trim(
            (string) $value
        );

        if ($value === '') {
            return null;
        }

        /*
         * Prefer strict YYYY-MM-DD validation.
         */
        if (
            preg_match(
                '/^\d{4}-\d{2}-\d{2}$/',
                $value
            ) === 1
        ) {
            $date =
                \DateTimeImmutable::createFromFormat(
                    '!Y-m-d',
                    $value
                );

            $errors =
                \DateTimeImmutable::getLastErrors();

            $valid =
                $date instanceof \DateTimeImmutable
                && (
                    $errors === false
                    || (
                        $errors['warning_count'] === 0
                        && $errors['error_count'] === 0
                    )
                )
                && $date->format('Y-m-d') === $value;

            return $valid
                ? $value
                : null;
        }

        /*
         * Preserve compatibility with formats accepted by
         * the original application.
         */
        $timestamp = strtotime(
            $value
        );

        if ($timestamp === false) {
            return null;
        }

        return date(
            'Y-m-d',
            $timestamp
        );
    }

    /**
     * Shift a date by the supplied DateTime modifier.
     */
    private static function shiftDate(
        ?string $date,
        string $modifier
    ): ?string {
        $date = self::normalizeDate(
            $date
        );

        if ($date === null) {
            return null;
        }

        try {
            $dateTime =
                new \DateTimeImmutable(
                    $date
                );

            return $dateTime
                ->modify($modifier)
                ->format('Y-m-d');
        } catch (\Exception) {
            return null;
        }
    }
}
