<?php

declare(strict_types=1);

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
 * @property ?int $update_comment
 */
class Issue extends \Model
{
    protected $_table_name = 'issue';

    protected $_heirarchy = null;

    protected $_children = null;

    protected static $requiredFields = [
        'type_id',
        'status',
        'name',
        'author_id',
    ];

    /**
     * Maximum hierarchy depth.
     *
     * Prevents infinite/corrupted trees from causing
     * uncontrolled recursion or resource exhaustion.
     */
    private const MAX_HIERARCHY_DEPTH = 1000;

    /**
     * Maximum title size accepted by the model.
     */
    private const MAX_NAME_LENGTH = 255;

    /**
     * Upper boundary for descriptions.
     *
     * This protects persistence/logging layers against
     * unexpectedly large input.
     */
    private const MAX_DESCRIPTION_LENGTH = 1_000_000;

    /**
     * Fields which may be supplied during issue creation.
     *
     * Explicit allowlisting prevents mass assignment.
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

    /**
     * Supported repeat cycles.
     */
    private const REPEAT_CYCLES = [
        'daily',
        'weekly',
        'monthly',
        'quarterly',
        'semi_annually',
        'annually',
        'sprint',
    ];

    /**
     * Fields considered relevant for notifications.
     */
    private const IMPORTANT_UPDATE_FIELDS = [
        'status',
        'name',
        'description',
        'owner_id',
        'priority',
        'due_date',
    ];

    /**
     * Fields that must never be included in an integrity state.
     */
    private const HASH_STATE_EXCLUDED_FIELDS = [
        'update_comment',
    ];

    /**
     * Create a new issue.
     */
    public static function create(array $data, bool $notify = true): static
    {
        $data = self::normalizeCreateData($data);

        /*
         * Prefer the authenticated identity instead of blindly trusting
         * an author_id supplied by the request.
         *
         * An existing internal caller may still explicitly provide
         * author_id, but an invalid value is discarded.
         */
        if (empty($data['author_id'])) {
            $currentUserId = self::positiveInt(
                \Base::instance()->get('user.id')
            );

            if ($currentUserId !== null) {
                $data['author_id'] = $currentUserId;
            }
        }

        self::validateRequiredCreateFields($data);

        self::validateParentForCurrentUser(
            $data['parent_id'] ?? null
        );

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
     * Normalize all user-controlled data before persistence.
     */
    private static function normalizeCreateData(array $data): array
    {
        if (array_key_exists('hours', $data)) {
            $hours = self::nullableNonNegativeFloat(
                $data['hours']
            );

            $data['hours_total'] = $hours;
            $data['hours_remaining'] = $hours;

            unset($data['hours']);
        }

        if (array_key_exists('name', $data)) {
            $data['name'] = self::sanitizeName(
                $data['name']
            );
        }

        if (array_key_exists('description', $data)) {
            $data['description'] = self::sanitizeDescription(
                $data['description']
            );
        }

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
                : max(0, (int) $priority);
        }

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

        if (isset($data['repeat_cycle'])) {
            $repeatCycle = is_string($data['repeat_cycle'])
                ? trim($data['repeat_cycle'])
                : '';

            $data['repeat_cycle'] = in_array(
                $repeatCycle,
                self::REPEAT_CYCLES,
                true
            )
                ? $repeatCycle
                : null;
        }

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
         * Control field: must never reach ORM persistence.
         */
        unset($data['due_date_sprint']);

        /*
         * Prevent mass assignment.
         */
        return array_intersect_key(
            $data,
            array_flip(self::CREATE_FIELDS)
        );
    }

    /**
     * Check mandatory creation fields.
     */
    private static function validateRequiredCreateFields(
        array $data
    ): void {
        foreach (self::$requiredFields as $field) {
            if (
                !array_key_exists($field, $data)
                || $data[$field] === null
                || $data[$field] === ''
            ) {
                throw new \InvalidArgumentException(
                    'Missing required issue field.'
                );
            }
        }

        if (
            !isset($data['name'])
            || trim((string) $data['name']) === ''
        ) {
            throw new \InvalidArgumentException(
                'Issue name is required.'
            );
        }
    }

    /**
     * Ensure a requested parent exists and is accessible
     * by the current user.
     */
    private static function validateParentForCurrentUser(
        mixed $parentId
    ): void {
        $parentId = self::positiveInt($parentId);

        if ($parentId === null) {
            return;
        }

        $parent = new Issue();
        $parent->load($parentId);

        if (!$parent->id) {
            throw new \InvalidArgumentException(
                'Invalid parent issue.'
            );
        }

        if (!$parent->allowAccess()) {
            /*
             * Do not reveal whether an inaccessible issue exists.
             */
            throw new \RuntimeException(
                'Parent issue is not available.'
            );
        }
    }

    /**
     * Get complete ancestor tree.
     */
    public function getAncestors(): array
    {
        if ($this->_heirarchy !== null) {
            return $this->_heirarchy;
        }

        $issues = [$this];
        $visited = [];

        if ($this->id) {
            $visited[(int) $this->id] = true;
        }

        $parentId = self::positiveInt(
            $this->parent_id
        );

        $depth = 0;

        while ($parentId !== null) {
            if (++$depth > self::MAX_HIERARCHY_DEPTH) {
                \Base::instance()->set(
                    'error',
                    'Issue hierarchy exceeds maximum depth.'
                );

                break;
            }

            if (isset($visited[$parentId])) {
                \Base::instance()->set(
                    'error',
                    'Invalid circular issue hierarchy detected.'
                );

                break;
            }

            $visited[$parentId] = true;

            $issue = new Issue();
            $issue->load($parentId);

            if (!$issue->id) {
                \Base::instance()->set(
                    'error',
                    'Invalid issue hierarchy.'
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
     * Normalize whitespace.
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
     * Soft delete.
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
     * Delete descendant tree.
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
            if ($child instanceof Issue) {
                $child->delete();
            }
        }

        return $this;
    }

    /**
     * Restore issue.
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
     * Restore descendant tree.
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
            if ($child instanceof Issue) {
                $child->restore();
            }
        }

        return $this;
    }

    /**
     * Generate repeated issue.
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
     * Create safe repeated issue object.
     */
    private function buildRepeatedIssue(): Issue
    {
        $issue = new Issue();

        $issue->name = self::sanitizeName(
            $this->name
        );

        $issue->type_id =
            $this->type_id;

        $issue->parent_id =
            $this->parent_id;

        $issue->author_id =
            $this->author_id;

        $issue->owner_id =
            $this->owner_id;

        $issue->description =
            self::sanitizeDescription(
                $this->description
            );

        $issue->priority =
            $this->priority;

        $issue->repeat_cycle =
            $this->repeat_cycle;

        $issue->hours_total =
            $this->hours_total;

        $issue->hours_remaining =
            $this->hours_total;

        $issue->created_date =
            date('Y-m-d H:i:s');

        return $issue;
    }

    /**
     * Calculate repeated dates.
     */
    private function applyRepeatDates(Issue $issue): void
    {
        $modifiers = [
            'daily' => '+1 day',
            'weekly' => '+1 week',
            'monthly' => '+1 month',
            'quarterly' => '+3 months',
            'semi_annually' => '+6 months',
            'annually' => '+1 year',
        ];

        if (
            isset(
                $modifiers[$issue->repeat_cycle]
            )
        ) {
            $modifier =
                $modifiers[$issue->repeat_cycle];

            $issue->start_date =
                $this->start_date
                    ? self::shiftDate(
                        $this->start_date,
                        $modifier
                    )
                    : null;

            $issue->due_date =
                self::shiftDate(
                    $this->due_date,
                    $modifier
                );

            return;
        }

        if ($issue->repeat_cycle === 'sprint') {
            $this->applyNextSprintDates(
                $issue
            );

            return;
        }

        $issue->repeat_cycle = null;
    }

    private function applyNextSprintDates(
        Issue $issue
    ): void {
        $sprint = new Sprint();

        $sprint->load(
            ['start_date > NOW()'],
            ['order' => 'start_date']
        );

        if (!$sprint->id) {
            return;
        }

        $issue->start_date =
            $this->start_date
                ? $sprint->start_date
                : null;

        $issue->due_date =
            $sprint->end_date;
    }

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
     * Log update securely.
     *
     * @return Issue\Update|false
     */
    protected function _saveUpdate(
        bool $notify = true
    ): Issue\Update|false {
        $f3 = \Base::instance();

        $this->validateParentRelationship();

        $userId = self::positiveInt(
            $f3->get('user.id')
        );

        if ($userId === null) {
            throw new \RuntimeException(
                'Authentication required.'
            );
        }

        $update = new Issue\Update();

        $update->issue_id =
            (int) $this->id;

        $update->user_id =
            $userId;

        $update->created_date =
            date('Y-m-d H:i:s');

        $update->notify = 0;

        if ($f3->exists('update_comment')) {
            $comment =
                $f3->get('update_comment');

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
        $this->handleRepeatAfterClose($notify);

        [
            $updated,
            $importantChanges,
        ] = $this->logChangedFields(
            $update
        );

        if ($updated === 0) {
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
     * Validate parent relation and prevent cycles.
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

        if (
            $this->id
            && (int) $this->id === $parentId
        ) {
            $this->parent_id =
                $this->_getPrev('parent_id');

            return;
        }

        $parent = new Issue();
        $parent->load($parentId);

        if (
            !$parent->id
            || !$parent->allowAccess()
            || $this->wouldCreateCircularHierarchy($parent)
        ) {
            $this->parent_id =
                $this->_getPrev('parent_id');

            return;
        }

        $this->parent_id = $parentId;
    }

    /**
     * Detect hierarchy tampering/cycles.
     */
    private function wouldCreateCircularHierarchy(
        Issue $parent
    ): bool {
        if (!$this->id) {
            return false;
        }

        $currentId =
            self::positiveInt($parent->id);

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

            $currentId =
                self::positiveInt(
                    $current->parent_id
                );
        }

        return false;
    }

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
     * @return array{0:int,1:int}
     */
    private function logChangedFields(
        Issue\Update $update
    ): array {
        $updated = 0;
        $important = 0;

        foreach ($this->fields as $key => $field) {
            if (empty($field['changed'])) {
                continue;
            }

            $current =
                $field['value'] ?? null;

            $previous =
                $this->_getPrev($key);

            if (
                !$this->valuesDiffer(
                    $current,
                    $previous
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
                $previous;

            $updateField->new_value =
                $current;

            $updateField->save();

            $updated++;

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
                $important++;
            }
        }

        return [$updated, $important];
    }

    private function valuesDiffer(
        mixed $current,
        mixed $previous
    ): bool {
        return rtrim(
            (string) ($current ?? '')
        ) !== rtrim(
            (string) ($previous ?? '')
        );
    }

    /**
     * Save issue.
     */
    public function save(bool $notify = true): Issue
    {
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

        /*
         * Invalidate cached relationship state.
         */
        $this->_children = null;
        $this->_heirarchy = null;

        return $issue;
    }

    private function normalizeBeforeSave(): void
    {
        if (
            $this->sprint_id === 0
            || $this->sprint_id === '0'
        ) {
            $this->sprint_id = null;
        }

        $this->name =
            self::sanitizeName($this->name);

        $this->description =
            self::sanitizeDescription(
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
        $this->censorSensitiveNumbers();
    }

    /**
     * Remove potential payment-card patterns.
     */
    private function censorSensitiveNumbers(): void
    {
        if (
            !\Base::instance()->get(
                'security.block_ccs'
            )
        ) {
            return;
        }

        $description =
            (string) ($this->description ?? '');

        $pattern =
            '/(?:\d{3,4}-){3}(\d{3,4})/';

        $filtered = preg_replace(
            $pattern,
            '************$1',
            $description
        );

        if ($filtered !== null) {
            $this->description =
                $filtered;
        }
    }

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

    private function setClosedDateFromStatus(): void
    {
        if (
            $this->closed_date
            || !$this->status
        ) {
            return;
        }

        $statusId =
            self::positiveInt($this->status);

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
     * Save hashtags.
     */
    public function saveTags(): Issue
    {
        $issueId =
            self::positiveInt($this->id);

        if ($issueId === null) {
            return $this;
        }

        $tag = new Issue\Tag();

        $tag->deleteByIssueId(
            $issueId
        );

        if (
            $this->deleted_date
            || !$this->description
        ) {
            return $this;
        }

        $count = preg_match_all(
            '/(?:(?<=#)|(?<=[^a-z\/&]#))'
            . '[a-z][a-z0-9_-]*[a-z0-9]+'
            . '(?=[^a-z\/]|$)/i',
            (string) $this->description,
            $matches
        );

        if (!$count) {
            return $this;
        }

        $saved = [];

        foreach ($matches[0] as $match) {
            $normalized = preg_replace(
                '/[_-]+/',
                '-',
                ltrim(
                    (string) $match,
                    '#'
                )
            );

            if (
                !$normalized
                || isset($saved[$normalized])
            ) {
                continue;
            }

            $tag->reset();

            $tag->tag = $normalized;
            $tag->issue_id = $issueId;
            $tag->save();

            $saved[$normalized] = true;
        }

        return $this;
    }

    /**
     * Duplicate issue.
     */
    public function duplicate(
        bool $recursive = true
    ): Issue {
        if (!$this->id) {
            throw new \RuntimeException(
                'Unable to duplicate issue.'
            );
        }

        if (!$this->allowAccess()) {
            throw new \RuntimeException(
                'Operation not permitted.'
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

    private function duplicateCurrentIssue(): Issue
    {
        $f3 = \Base::instance();

        $this->copyto(
            'duplicating_issue'
        );

        foreach (
            [
                'id',
                'due_date',
                'hours_spent',
                'closed_date',
                'deleted_date',
            ] as $field
        ) {
            $f3->clear(
                'duplicating_issue.' . $field
            );
        }

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
                $child->duplicateCurrentIssue();

            $newChild->parent_id =
                $newId;

            $newChild->save(false);

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
     * Reset child sprint safely using bound parameters.
     */
    public function resetTaskSprints(
        bool $replaceExisting = true
    ): Issue {
        $sprintId =
            self::positiveInt($this->sprint_id);

        $issueId =
            self::positiveInt($this->id);

        $projectType =
            self::positiveInt(
                \Base::instance()->get(
                    'issue_type.project'
                )
            );

        if (
            $sprintId === null
            || $issueId === null
            || $projectType === null
        ) {
            return $this;
        }

        $query =
            'UPDATE issue '
            . 'SET sprint_id = :sprint '
            . 'WHERE parent_id = :issue '
            . 'AND type_id != :type';

        if ($replaceExisting) {
            $query .=
                ' AND sprint_id IS NULL';
        }

        $this->db->exec(
            $query,
            [
                ':sprint' => $sprintId,
                ':issue' => $issueId,
                ':type' => $projectType,
            ]
        );

        return $this;
    }

    public function getChildren(): array
    {
        if ($this->_children !== null) {
            return $this->_children;
        }

        if (!$this->id) {
            return [];
        }

        $children = $this->find([
            'parent_id = ? AND deleted_date IS NULL',
            $this->id,
        ]);

        $this->_children =
            is_array($children)
                ? $children
                : iterator_to_array($children ?? []);

        return $this->_children;
    }

    /**
     * Generate authenticated field-state hashes.
     *
     * HMAC prevents a client from creating a valid state hash
     * without possession of the server-side secret.
     */
    public function hashState(): array
    {
        $result = $this->cast();

        $key = self::integrityKey();

        foreach ($result as $field => &$value) {
            if (
                in_array(
                    $field,
                    self::HASH_STATE_EXCLUDED_FIELDS,
                    true
                )
            ) {
                unset($result[$field]);
                continue;
            }

            $value = hash_hmac(
                'sha256',
                self::normalizeHashValue($value),
                $key
            );
        }

        unset($value);

        return $result;
    }

    /**
     * Verify a supplied state hash using timing-resistant comparison.
     */
    public static function verifyStateHash(
        mixed $value,
        mixed $providedHash
    ): bool {
        if (
            !is_string($providedHash)
            || preg_match(
                '/^[a-f0-9]{64}$/i',
                $providedHash
            ) !== 1
        ) {
            return false;
        }

        $expected = hash_hmac(
            'sha256',
            self::normalizeHashValue($value),
            self::integrityKey()
        );

        return hash_equals(
            $expected,
            strtolower($providedHash)
        );
    }

    /**
     * Read integrity key from server-side configuration.
     *
     * There is deliberately no predictable fallback.
     */
    private static function integrityKey(): string
    {
        $f3 = \Base::instance();

        $key = $f3->get(
            'security.issue_integrity_key'
        );

        if (
            !is_string($key)
            || strlen($key) < 32
        ) {
            throw new \RuntimeException(
                'Issue integrity key is not configured correctly.'
            );
        }

        return $key;
    }

    private static function normalizeHashValue(
        mixed $value
    ): string {
        if ($value === null) {
            return '';
        }

        if (is_bool($value)) {
            return $value ? '1' : '0';
        }

        if (is_scalar($value)) {
            return (string) $value;
        }

        return json_encode(
            $value,
            JSON_THROW_ON_ERROR
        );
    }

    public function close(): Issue
    {
        if (
            !$this->id
            || $this->closed_date
        ) {
            return $this;
        }

        if (!$this->allowAccess()) {
            throw new \RuntimeException(
                'Operation not permitted.'
            );
        }

        $status = new Issue\Status();

        $status->load([
            'closed = ?',
            1,
        ]);

        if (!$status->id) {
            throw new \RuntimeException(
                'Unable to close issue.'
            );
        }

        $this->status =
            (int) $status->id;

        $this->closed_date =
            date('Y-m-d H:i:s');

        $this->save();

        return $this;
    }

    /**
     * Get all descendants.
     */
    public function descendantIds(): array
    {
        if (!$this->id) {
            return [];
        }

        return $this->collectDescendantIds(
            [],
            0
        );
    }

    /**
     * @param array<int,bool> $visited
     */
    private function collectDescendantIds(
        array $visited,
        int $depth
    ): array {
        if (
            $depth > self::MAX_HIERARCHY_DEPTH
        ) {
            return [];
        }

        $id = (int) $this->id;

        if (
            $id <= 0
            || isset($visited[$id])
        ) {
            return [];
        }

        $visited[$id] = true;

        $ids = [$id];

        foreach ($this->getChildren() as $child) {
            if (!$child instanceof Issue) {
                continue;
            }

            $ids = array_merge(
                $ids,
                $child->collectDescendantIds(
                    $visited,
                    $depth + 1
                )
            );
        }

        return array_values(
            array_unique($ids)
        );
    }

    /**
     * Aggregate project statistics.
     */
    public function projectStats(): array
    {
        $stats = [
            'total' => 0,
            'complete' => 0,
            'hours_spent' => 0.0,
            'hours_total' => 0.0,
        ];

        if (!$this->id) {
            return $stats;
        }

        $stats['total'] = 1;

        if ($this->closed_date) {
            $stats['complete'] = 1;
        }

        $stats['hours_spent'] = max(
            0.0,
            (float) ($this->hours_spent ?? 0)
        );

        $stats['hours_total'] = max(
            0.0,
            (float) ($this->hours_total ?? 0)
        );

        foreach ($this->getChildren() as $child) {
            if (!$child instanceof Issue) {
                continue;
            }

            $childStats =
                $child->projectStats();

            $stats['total'] +=
                (int) $childStats['total'];

            $stats['complete'] +=
                (int) $childStats['complete'];

            $stats['hours_spent'] +=
                (float) $childStats['hours_spent'];

            $stats['hours_total'] +=
                (float) $childStats['hours_total'];
        }

        return $stats;
    }

    /**
     * Least-privilege access check.
     */
    public function allowAccess(
        ?\Model\User $user = null
    ): bool {
        $f3 = \Base::instance();

        if (!$user instanceof \Model\User) {
            $candidate =
                $f3->get('user_obj');

            if (
                !$candidate instanceof \Model\User
            ) {
                /*
                 * Fail closed.
                 */
                return false;
            }

            $user = $candidate;
        }

        $userId =
            self::positiveInt($user->id);

        if ($userId === null) {
            return false;
        }

        /*
         * Preserve existing administrator behavior.
         */
        if ($user->role === 'admin') {
            return true;
        }

        /*
         * Deleted records are not visible to normal users.
         */
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

        $ownerId =
            self::positiveInt(
                $this->owner_id
            );

        $authorId =
            self::positiveInt(
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

    private static function sanitizeName(
        mixed $value
    ): string {
        if (!is_scalar($value)) {
            return '';
        }

        $value = trim(
            (string) $value
        );

        /*
         * Remove null bytes/control characters.
         */
        $value = preg_replace(
            '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u',
            '',
            $value
        ) ?? '';

        if (function_exists('mb_substr')) {
            return mb_substr(
                $value,
                0,
                self::MAX_NAME_LENGTH
            );
        }

        return substr(
            $value,
            0,
            self::MAX_NAME_LENGTH
        );
    }

    /**
     * Normalize description without destroying Markdown/Textile.
     *
     * HTML escaping remains an output-layer responsibility.
     */
    private static function sanitizeDescription(
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

        $value = preg_replace(
            '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u',
            '',
            $value
        ) ?? '';

        if (
            function_exists('mb_strlen')
            && mb_strlen($value) >
                self::MAX_DESCRIPTION_LENGTH
        ) {
            $value = mb_substr(
                $value,
                0,
                self::MAX_DESCRIPTION_LENGTH
            );
        } elseif (
            !function_exists('mb_strlen')
            && strlen($value) >
                self::MAX_DESCRIPTION_LENGTH
        ) {
            $value = substr(
                $value,
                0,
                self::MAX_DESCRIPTION_LENGTH
            );
        }

        return $value;
    }

    /**
     * Validate positive integer identifiers.
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
            : (int) $result;
    }

    /**
     * Validate non-negative numeric values.
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

        if (!is_numeric($value)) {
            return null;
        }

        $number = (float) $value;

        if (
            !is_finite($number)
            || $number < 0
        ) {
            return null;
        }

        return $number;
    }

    /**
     * Strict date validation.
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

            if (
                $date instanceof \DateTimeImmutable
                && (
                    $errors === false
                    || (
                        $errors['warning_count'] === 0
                        && $errors['error_count'] === 0
                    )
                )
                && $date->format('Y-m-d') === $value
            ) {
                return $value;
            }

            return null;
        }

        /*
         * Kept for compatibility with the original application,
         * which accepted alternative date formats.
         */
        $timestamp = strtotime($value);

        if ($timestamp === false) {
            return null;
        }

        return date(
            'Y-m-d',
            $timestamp
        );
    }

    private static function shiftDate(
        ?string $date,
        string $modifier
    ): ?string {
        $date =
            self::normalizeDate($date);

        if ($date === null) {
            return null;
        }

        try {
            $dateTime =
                new \DateTimeImmutable($date);

            $modified =
                $dateTime->modify($modifier);

            return $modified->format(
                'Y-m-d'
            );
        } catch (\Throwable) {
            return null;
        }
    }
}
