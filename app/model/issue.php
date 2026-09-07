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
     * Create and save a new issue.
     */
    public static function create(array $data, bool $notify = true): static
    {
        $data = self::normalizeCreateData($data);

        if (empty($data['author_id'])) {
            $userId = \Base::instance()->get('user.id');

            if ($userId) {
                $data['author_id'] = (int) $userId;
            }
        }

        /** @var static $item */
        $item = parent::create($data);

        if ($notify && $item->id) {
            \Helper\Notification::instance()->issue_create(
                (int) $item->id
            );
        }

        return $item;
    }

    /**
     * Normalize input used when creating an issue.
     */
    private static function normalizeCreateData(array $data): array
    {
        if (array_key_exists('hours', $data)) {
            $hours = self::normalizeNullableFloat($data['hours']);

            $data['hours_total'] = $hours;
            $data['hours_remaining'] = $hours;

            unset($data['hours']);
        }

        if (!empty($data['due_date'])) {
            $dueDate = self::normalizeDate(
                (string) $data['due_date']
            );

            $data['due_date'] = $dueDate;

            if (
                $dueDate !== null
                && empty($data['sprint_id'])
                && !empty($data['due_date_sprint'])
            ) {
                $sprint = new Sprint();

                $sprint->load([
                    'DATE(?) BETWEEN start_date AND end_date',
                    $dueDate,
                ]);

                if ($sprint->id) {
                    $data['sprint_id'] = $sprint->id;
                }
            }
        }

        return $data;
    }

    /**
     * Get complete parent list for issue.
     */
    public function getAncestors(): array
    {
        if ($this->_heirarchy !== null) {
            return $this->_heirarchy;
        }

        $issues = [$this];
        $issueIds = [(int) $this->id];
        $parentId = $this->parent_id;

        while ($parentId) {
            $parentId = (int) $parentId;

            if (in_array($parentId, $issueIds, true)) {
                \Base::instance()->set(
                    'error',
                    "Issue parent tree contains an infinite loop. "
                    . "Issue {$parentId} is the first point of recursion."
                );

                break;
            }

            $issue = new Issue();
            $issue->load($parentId);

            if (!$issue->id) {
                \Base::instance()->set(
                    'error',
                    "Issue parent tree references a nonexistent "
                    . "parent issue #{$parentId}."
                );

                break;
            }

            $issues[] = $issue;
            $issueIds[] = (int) $issue->id;
            $parentId = $issue->parent_id;
        }

        $this->_heirarchy = array_reverse($issues);

        return $this->_heirarchy;
    }

    /**
     * Remove messy whitespace from a string.
     */
    public static function clean(string $string): string
    {
        $normalized = str_replace(
            "\r\n",
            "\n",
            $string
        );

        return preg_replace(
            '/(?:(?:\r\n|\r|\n)\s*){2}/s',
            "\n\n",
            $normalized
        ) ?? $normalized;
    }

    /**
     * Delete without sending notification.
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
        $children = $this->find([
            'parent_id = ?',
            $this->id,
        ]);

        foreach ($children as $child) {
            $child->delete();
        }

        return $this;
    }

    /**
     * Restore a deleted issue without notifying.
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
        $children = $this->find([
            'parent_id = ? AND deleted_date IS NOT NULL',
            $this->id,
        ]);

        foreach ($children as $child) {
            $child->restore();
        }

        return $this;
    }

    /**
     * Repeat an issue by generating a minimal copy
     * and setting a new due date.
     */
    public function repeat(bool $notify = true): Issue
    {
        $repeatIssue = $this->buildRepeatIssue();

        $this->applyRepeatDates($repeatIssue);
        $this->assignSprintForRepeatedIssue($repeatIssue);

        $repeatIssue->save();

        if ($notify && $repeatIssue->id) {
            \Helper\Notification::instance()->issue_create(
                (int) $repeatIssue->id
            );
        }

        return $repeatIssue;
    }

    /**
     * Build the base copy used by repeat().
     */
    private function buildRepeatIssue(): Issue
    {
        $repeatIssue = new Issue();

        $repeatIssue->name = $this->name;
        $repeatIssue->type_id = $this->type_id;
        $repeatIssue->parent_id = $this->parent_id;
        $repeatIssue->author_id = $this->author_id;
        $repeatIssue->owner_id = $this->owner_id;
        $repeatIssue->description = $this->description;
        $repeatIssue->priority = $this->priority;
        $repeatIssue->repeat_cycle = $this->repeat_cycle;
        $repeatIssue->hours_total = $this->hours_total;
        $repeatIssue->hours_remaining = $this->hours_total;
        $repeatIssue->created_date = date('Y-m-d H:i:s');

        return $repeatIssue;
    }

    /**
     * Apply dates to a repeated issue according to its repeat cycle.
     */
    private function applyRepeatDates(Issue $repeatIssue): void
    {
        switch ($repeatIssue->repeat_cycle) {
            case 'daily':
                $repeatIssue->start_date = $this->start_date
                    ? date('Y-m-d', strtotime('tomorrow'))
                    : null;

                $repeatIssue->due_date = date(
                    'Y-m-d',
                    strtotime('tomorrow')
                );

                return;

            case 'weekly':
                $repeatIssue->start_date = $this->shiftDate(
                    $this->start_date,
                    '+1 week'
                );

                $repeatIssue->due_date = $this->shiftDate(
                    $this->due_date,
                    '+1 week'
                );

                return;

            case 'monthly':
                $repeatIssue->start_date = $this->shiftDate(
                    $this->start_date,
                    '+1 month'
                );

                $repeatIssue->due_date = $this->shiftDate(
                    $this->due_date,
                    '+1 month'
                );

                return;

            case 'quarterly':
                $repeatIssue->start_date = $this->shiftDate(
                    $this->start_date,
                    '+3 months'
                );

                $repeatIssue->due_date = $this->shiftDate(
                    $this->due_date,
                    '+3 months'
                );

                return;

            case 'semi_annually':
                $repeatIssue->start_date = $this->shiftDate(
                    $this->start_date,
                    '+6 months'
                );

                $repeatIssue->due_date = $this->shiftDate(
                    $this->due_date,
                    '+6 months'
                );

                return;

            case 'annually':
                $repeatIssue->start_date = $this->shiftDate(
                    $this->start_date,
                    '+1 year'
                );

                $repeatIssue->due_date = $this->shiftDate(
                    $this->due_date,
                    '+1 year'
                );

                return;

            case 'sprint':
                $sprint = new Sprint();

                $sprint->load(
                    ['start_date > NOW()'],
                    ['order' => 'start_date']
                );

                if ($sprint->id) {
                    $repeatIssue->start_date = $this->start_date
                        ? $sprint->start_date
                        : null;

                    $repeatIssue->due_date = $sprint->end_date;
                }

                return;

            default:
                $repeatIssue->repeat_cycle = null;
        }
    }

    /**
     * Assign a repeated issue to the sprint covering its new due date.
     */
    private function assignSprintForRepeatedIssue(
        Issue $repeatIssue
    ): void {
        if (
            !$this->sprint_id
            || !$repeatIssue->due_date
        ) {
            return;
        }

        $sprint = new Sprint();

        $sprint->load(
            [
                'end_date >= ? AND start_date <= ?',
                $repeatIssue->due_date,
                $repeatIssue->due_date,
            ],
            [
                'order' => 'start_date',
            ]
        );

        if ($sprint->id) {
            $repeatIssue->sprint_id = $sprint->id;
        }
    }

    /**
     * Shift a date while preserving null values.
     */
    private function shiftDate(
        ?string $date,
        string $modifier
    ): ?string {
        if (!$date) {
            return null;
        }

        $timestamp = strtotime(
            $date . ' ' . $modifier
        );

        return $timestamp === false
            ? null
            : date('Y-m-d', $timestamp);
    }

    /**
     * Log and save an issue update.
     */
    protected function _saveUpdate(
        bool $notify = true
    ): Issue\Update|false {
        $f3 = \Base::instance();

        /*
         * Prevent an issue from referencing itself as its own parent.
         */
        if (
            (int) $this->id
            === (int) $this->parent_id
        ) {
            $this->parent_id = $this->_getPrev(
                'parent_id'
            );
        }

        $update = new Issue\Update();

        $update->issue_id = $this->id;
        $update->user_id = $f3->get('user.id');
        $update->created_date = date(
            'Y-m-d H:i:s'
        );

        $update->notify = 0;

        if ($f3->exists('update_comment')) {
            $comment = $f3->get(
                'update_comment'
            );

            if (
                $comment
                && $comment->id
            ) {
                $update->comment_id = $comment->id;
                $update->notify = (int) $notify;
            }
        }

        $update->save();

        $this->normalizeHoursAfterUpdate();
        $this->handleRepeatAfterClose($notify);

        [
            $updatedFields,
            $importantChanges,
        ] = $this->logChangedFields($update);

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
     * Normalize hour values after an update.
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
            && $this->hours_remaining
        ) {
            $this->hours_remaining = 0;
        }
    }

    /**
     * Create the next issue for a repeating issue
     * that has just been closed.
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
     * Persist field-level update history.
     *
     * @return array{0:int,1:int}
     */
    private function logChangedFields(
        Issue\Update $update
    ): array {
        $updated = 0;
        $importantChanges = 0;

        foreach ($this->fields as $key => $field) {
            $currentValue =
                $field['value'] ?? null;

            $previousValue =
                $this->_getPrev($key);

            if (
                empty($field['changed'])
                || !$this->valuesDiffer(
                    $currentValue,
                    $previousValue
                )
            ) {
                continue;
            }

            $updateField =
                new Issue\Update\Field();

            $updateField->issue_update_id =
                $update->id;

            $updateField->field =
                $key;

            $updateField->old_value =
                $previousValue;

            $updateField->new_value =
                $currentValue;

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
                $importantChanges++;
            }
        }

        return [
            $updated,
            $importantChanges,
        ];
    }

    /**
     * Compare ORM values while keeping the previous
     * whitespace-tolerant behavior.
     */
    private function valuesDiffer(
        mixed $currentValue,
        mixed $previousValue
    ): bool {
        return rtrim(
            (string) ($currentValue ?? '')
        ) !== rtrim(
            (string) ($previousValue ?? '')
        );
    }

    /**
     * Log issue update and send notifications.
     */
    public function save(
        bool $notify = true
    ): Issue {
        $f3 = \Base::instance();

        if ($this->sprint_id === 0) {
            $this->set(
                'sprint_id',
                null
            );
        }

        $this->censorCreditCardNumbers($f3);
        $this->normalizeDates();
        $this->normalizeRepeatCycle();

        if ($this->query) {
            $update =
                $this->_saveUpdate($notify);

            $issue =
                parent::save();

            if (
                $notify
                && $update !== false
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

            $issue = parent::save();
        }

        $this->saveTags();

        return $issue;
    }

    /**
     * Censor credit-card-like values when configured.
     */
    private function censorCreditCardNumbers(
        \Base $f3
    ): void {
        $description =
            (string) ($this->description ?? '');

        if (
            !$f3->get(
                'security.block_ccs'
            )
        ) {
            return;
        }

        if (
            preg_match(
                '/(?:\d{3,4}-){3}\d{3,4}/',
                $description
            ) !== 1
        ) {
            return;
        }

        $censored = preg_replace(
            '/(?:\d{3,4}-){3}(\d{3,4})/',
            '************$1',
            $description
        );

        if ($censored !== null) {
            $this->set(
                'description',
                $censored
            );
        }
    }

    /**
     * Normalize issue dates before persistence.
     */
    private function normalizeDates(): void
    {
        $this->due_date =
            self::normalizeDate(
                $this->due_date
            );

        $this->start_date =
            self::normalizeDate(
                $this->start_date
            );
    }

    /**
     * Keep only supported repeat-cycle values.
     */
    private function normalizeRepeatCycle(): void
    {
        if (
            !in_array(
                $this->repeat_cycle,
                self::REPEAT_CYCLES,
                true
            )
        ) {
            $this->repeat_cycle = null;
        }
    }

    /**
     * Set closed_date when creating an issue
     * directly in a closed status.
     */
    private function setClosedDateFromStatus(): void
    {
        if (
            $this->closed_date
            || !$this->status
        ) {
            return;
        }

        $status = new Issue\Status();

        $status->load(
            $this->status
        );

        if (
            $status->id
            && $status->closed
        ) {
            $this->closed_date =
                date('Y-m-d H:i:s');
        }
    }

    /**
     * Finds and saves the current issue's tags.
     */
    public function saveTags(): Issue
    {
        $tag = new Issue\Tag();

        if ($this->id) {
            $tag->deleteByIssueId(
                (int) $this->id
            );
        }

        if (
            $this->deleted_date
            || !$this->id
        ) {
            return $this;
        }

        $description =
            (string) ($this->description ?? '');

        $count = preg_match_all(
            '/(?<=[^a-z\\/&]#|^#)'
            . '[a-z][a-z0-9_-]*[a-z0-9]+'
            . '(?=[^a-z\\/]|$)/i',
            $description,
            $matches
        );

        if (!$count) {
            return $this;
        }

        $savedTags = [];

        foreach ($matches[0] as $match) {
            $normalizedTag = preg_replace(
                '/[_-]+/',
                '-',
                ltrim($match, '#')
            );

            if (
                !$normalizedTag
                || isset(
                    $savedTags[$normalizedTag]
                )
            ) {
                continue;
            }

            $tag->reset();

            $tag->tag =
                $normalizedTag;

            $tag->issue_id =
                $this->id;

            $tag->save();

            $savedTags[$normalizedTag] =
                true;
        }

        return $this;
    }

    /**
     * Duplicate issue and all sub-issues.
     *
     * @throws \Exception
     */
    public function duplicate(
        bool $recursive = true
    ): Issue {
        if (!$this->id) {
            throw new \Exception(
                'Cannot duplicate an issue that '
                . 'is not yet saved.'
            );
        }

        $newIssue =
            $this->duplicateCurrentIssue();

        if ($recursive) {
            $this->_duplicateTree(
                (int) $this->id,
                (int) $newIssue->id
            );
        }

        return $newIssue;
    }

    /**
     * Duplicate the current issue without
     * recursively copying children.
     */
    private function duplicateCurrentIssue(): Issue
    {
        $f3 = \Base::instance();

        $this->copyto(
            'duplicating_issue'
        );

        $f3->clear(
            'duplicating_issue.id'
        );

        $f3->clear(
            'duplicating_issue.due_date'
        );

        $f3->clear(
            'duplicating_issue.hours_spent'
        );

        $newIssue = new Issue();

        $newIssue->copyfrom(
            'duplicating_issue'
        );

        $newIssue->author_id =
            $f3->get('user.id');

        $newIssue->hours_remaining =
            $newIssue->hours_total;

        $newIssue->created_date =
            date('Y-m-d H:i:s');

        $newIssue->save();

        return $newIssue;
    }

    /**
     * Duplicate a complete issue tree.
     */
    protected function _duplicateTree(
        int $id,
        int $newId
    ): Issue {
        $children = $this->find([
            'parent_id = ?',
            $id,
        ]);

        foreach ($children as $child) {
            if ($child->deleted_date) {
                continue;
            }

            $newChild =
                $this->duplicateChildIssue(
                    $child,
                    $newId
                );

            $this->_duplicateTree(
                (int) $child->id,
                (int) $newChild->id
            );
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

        $f3->clear(
            'duplicating_issue.id'
        );

        $f3->clear(
            'duplicating_issue.due_date'
        );

        $f3->clear(
            'duplicating_issue.hours_spent'
        );

        $newChild = new Issue();

        $newChild->copyfrom(
            'duplicating_issue'
        );

        $newChild->author_id =
            $f3->get('user.id');

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
     * Move all non-project children to the same sprint.
     */
    public function resetTaskSprints(
        bool $replaceExisting = true
    ): Issue {
        if (!$this->sprint_id) {
            return $this;
        }

        $f3 = \Base::instance();

        $query =
            'UPDATE issue '
            . 'SET sprint_id = :sprint '
            . 'WHERE parent_id = :issue '
            . 'AND type_id != :type';

        /*
         * Preserve existing behavior:
         * only children without sprint are changed.
         */
        if ($replaceExisting) {
            $query .=
                ' AND sprint_id IS NULL';
        }

        $this->db->exec(
            $query,
            [
                ':sprint' =>
                    $this->sprint_id,

                ':issue' =>
                    $this->id,

                ':type' =>
                    $f3->get(
                        'issue_type.project'
                    ),
            ]
        );

        return $this;
    }

    /**
     * Get children of current issue.
     */
    public function getChildren(): array
    {
        if ($this->_children !== null) {
            return $this->_children;
        }

        $this->_children = $this->find([
            'parent_id = ? '
            . 'AND deleted_date IS NULL',
            $this->id,
        ]);

        return $this->_children;
    }

    /**
     * Generate MD5 hashes for each column.
     *
     * MD5 is retained for compatibility with
     * the existing client/server change-state protocol.
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
            $status->id;

        $this->closed_date =
            date('Y-m-d H:i:s');

        $this->save();

        return $this;
    }

    /**
     * Get array of all descendant IDs.
     */
    public function descendantIds(): array
    {
        $ids = [
            (int) $this->id,
        ];

        foreach (
            $this->getChildren() as $child
        ) {
            $ids = array_merge(
                $ids,
                $child->descendantIds()
            );
        }

        return array_values(
            array_unique($ids)
        );
    }

    /**
     * Get aggregate totals across project
     * and descendants.
     */
    public function projectStats(): array
    {
        $stats = [
            'total' => 0,
            'complete' => 0,
            'hours_spent' => 0,
            'hours_total' => 0,
        ];

        if (!$this->id) {
            return $stats;
        }

        $stats['total'] = 1;

        $stats['complete'] =
            $this->closed_date
                ? 1
                : 0;

        $stats['hours_spent'] = max(
            0,
            (float) (
                $this->hours_spent ?? 0
            )
        );

        $stats['hours_total'] = max(
            0,
            (float) (
                $this->hours_total ?? 0
            )
        );

        foreach (
            $this->getChildren() as $child
        ) {
            $childStats =
                $child->projectStats();

            $stats['total'] +=
                $childStats['total'];

            $stats['complete'] +=
                $childStats['complete'];

            $stats['hours_spent'] +=
                $childStats['hours_spent'];

            $stats['hours_total'] +=
                $childStats['hours_total'];
        }

        return $stats;
    }

    /**
     * Check if the current/given user
     * should be allowed access to the issue.
     */
    public function allowAccess(
        ?\Model\User $user = null
    ): bool {
        $f3 = \Base::instance();

        if (!$user instanceof \Model\User) {
            $candidate =
                $f3->get('user_obj');

            if (
                !$candidate instanceof
                \Model\User
            ) {
                return false;
            }

            $user = $candidate;
        }

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

        if (
            (int) $this->owner_id
            === (int) $user->id
            ||
            (int) $this->author_id
            === (int) $user->id
        ) {
            return true;
        }

        $groupIds =
            \Helper\Dashboard::instance()
                ->getGroupIds();

        $normalizedGroupIds =
            array_map(
                'intval',
                is_array($groupIds)
                    ? $groupIds
                    : []
            );

        return $this->owner_id !== null
            && in_array(
                (int) $this->owner_id,
                $normalizedGroupIds,
                true
            );
    }

    /**
     * Normalize a date to Y-m-d.
     */
    private static function normalizeDate(
        mixed $value
    ): ?string {
        if (
            $value === null
            || $value === ''
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
                $date instanceof
                    \DateTimeImmutable
                &&
                (
                    $errors === false
                    ||
                    (
                        $errors['warning_count']
                            === 0
                        &&
                        $errors['error_count']
                            === 0
                    )
                )
                &&
                $date->format('Y-m-d')
                    === $value
            ) {
                return $value;
            }
        }

        $timestamp =
            strtotime($value);

        return $timestamp === false
            ? null
            : date(
                'Y-m-d',
                $timestamp
            );
    }

    /**
     * Normalize optional numeric hour values.
     */
    private static function normalizeNullableFloat(
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

        return (float) $value;
    }
}

