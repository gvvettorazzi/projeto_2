<?php

namespace Model;

class Issue extends \Model
{
    private const MAX_HIERARCHY_DEPTH = 100;

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
     * Create a new issue.
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

        if ($notify && $item->id) {
            \Helper\Notification::instance()
                ->issue_create((int) $item->id);
        }

        return $item;
    }

    /**
     * Normalize values received when creating an issue.
     */
    private static function normalizeCreateData(array $data): array
    {
        if (isset($data['name'])) {
            $data['name'] = trim((string) $data['name']);
        }

        if (isset($data['description'])) {
            $data['description'] = self::clean(
                (string) $data['description']
            );
        }

        foreach (
            [
                'type_id',
                'status',
                'author_id',
                'owner_id',
                'parent_id',
                'sprint_id',
                'priority',
            ] as $field
        ) {
            if (!array_key_exists($field, $data)) {
                continue;
            }

            if (
                in_array(
                    $field,
                    ['owner_id', 'parent_id', 'sprint_id'],
                    true
                )
            ) {
                $data[$field] = self::nullablePositiveInt(
                    $data[$field]
                );
            } else {
                $normalized = self::positiveInt($data[$field]);

                if ($normalized !== null) {
                    $data[$field] = $normalized;
                }
            }
        }

        if (array_key_exists('hours', $data)) {
            $hours = self::nullableNonNegativeFloat(
                $data['hours']
            );

            $data['hours_total'] = $hours;
            $data['hours_remaining'] = $hours;

            unset($data['hours']);
        }

        foreach (
            [
                'hours_total',
                'hours_remaining',
                'hours_spent',
            ] as $field
        ) {
            if (array_key_exists($field, $data)) {
                $data[$field] =
                    self::nullableNonNegativeFloat(
                        $data[$field]
                    );
            }
        }

        foreach (
            ['start_date', 'due_date'] as $field
        ) {
            if (
                array_key_exists($field, $data)
                && $data[$field] !== null
                && $data[$field] !== ''
            ) {
                $data[$field] = self::normalizeDate(
                    $data[$field]
                );
            }
        }

        if (
            empty($data['sprint_id'])
            && !empty($data['due_date'])
            && !empty($data['due_date_sprint'])
        ) {
            $sprint = new Sprint();

            $sprint->load([
                'DATE(?) BETWEEN start_date AND end_date',
                $data['due_date'],
            ]);

            if ($sprint->id) {
                $data['sprint_id'] =
                    (int) $sprint->id;
            }
        }

        if (isset($data['repeat_cycle'])) {
            $data['repeat_cycle'] =
                self::normalizeRepeatCycle(
                    $data['repeat_cycle']
                );
        }

        return $data;
    }

    /**
     * Get issue ancestors and protect against circular hierarchy.
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

        while (
            $parentId !== null
            && $depth < self::MAX_HIERARCHY_DEPTH
        ) {
            if (isset($visited[$parentId])) {
                \Base::instance()->set(
                    'error',
                    'Issue parent tree contains a circular reference.'
                );

                break;
            }

            $visited[$parentId] = true;

            $issue = new Issue();
            $issue->load($parentId);

            if (!$issue->id) {
                \Base::instance()->set(
                    'error',
                    'Issue parent tree references an invalid issue.'
                );

                break;
            }

            $issues[] = $issue;

            $parentId = self::positiveInt(
                $issue->parent_id
            );

            $depth++;
        }

        if (
            $depth >= self::MAX_HIERARCHY_DEPTH
            && $parentId !== null
        ) {
            \Base::instance()->set(
                'error',
                'Issue hierarchy exceeded the permitted depth.'
            );
        }

        $this->_heirarchy =
            array_reverse($issues);

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

        $result = preg_replace(
            '/(?:\n\s*){2,}/',
            "\n\n",
            $string
        );

        return trim(
            $result ?? $string
        );
    }

    /**
     * Soft-delete issue.
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
     * Delete descendant issues.
     */
    protected function _deleteTree(): Issue
    {
        foreach (
            $this->find([
                'parent_id = ?',
                $this->id,
            ]) as $child
        ) {
            $child->delete();
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
     * Restore descendants.
     */
    protected function _restoreTree(): Issue
    {
        foreach (
            $this->find([
                'parent_id = ? AND deleted_date IS NOT NULL',
                $this->id,
            ]) as $child
        ) {
            $child->restore();
        }

        return $this;
    }

    /**
     * Repeat issue.
     */
    public function repeat(bool $notify = true): Issue
    {
        $repeat = new Issue();

        $repeat->name = trim(
            (string) $this->name
        );

        $repeat->type_id =
            (int) $this->type_id;

        $repeat->parent_id =
            self::nullablePositiveInt(
                $this->parent_id
            );

        $repeat->author_id =
            (int) $this->author_id;

        $repeat->owner_id =
            self::nullablePositiveInt(
                $this->owner_id
            );

        $repeat->description =
            self::clean(
                (string) $this->description
            );

        $repeat->priority =
            (int) $this->priority;

        $repeat->repeat_cycle =
            self::normalizeRepeatCycle(
                $this->repeat_cycle
            );

        $repeat->hours_total =
            self::nullableNonNegativeFloat(
                $this->hours_total
            );

        $repeat->hours_remaining =
            $repeat->hours_total;

        $repeat->created_date =
            date('Y-m-d H:i:s');

        $this->applyRepeatDates($repeat);

        if (
            $this->sprint_id
            && $repeat->due_date
        ) {
            $sprint = new Sprint();

            $sprint->load(
                [
                    'end_date >= ? AND start_date <= ?',
                    $repeat->due_date,
                    $repeat->due_date,
                ],
                [
                    'order' => 'start_date',
                ]
            );

            if ($sprint->id) {
                $repeat->sprint_id =
                    (int) $sprint->id;
            }
        }

        $repeat->save();

        if ($notify && $repeat->id) {
            \Helper\Notification::instance()
                ->issue_create(
                    (int) $repeat->id
                );
        }

        return $repeat;
    }

    /**
     * Calculate dates for a recurring issue.
     */
    private function applyRepeatDates(
        Issue $repeat
    ): void {
        switch ($repeat->repeat_cycle) {
            case 'daily':
                $repeat->start_date =
                    $this->start_date
                        ? date(
                            'Y-m-d',
                            strtotime('tomorrow')
                        )
                        : null;

                $repeat->due_date =
                    date(
                        'Y-m-d',
                        strtotime('tomorrow')
                    );
                break;

            case 'weekly':
                $repeat->start_date =
                    self::shiftDate(
                        $this->start_date,
                        '+1 week'
                    );

                $repeat->due_date =
                    self::shiftDate(
                        $this->due_date,
                        '+1 week'
                    );
                break;

            case 'monthly':
                $repeat->start_date =
                    self::shiftDate(
                        $this->start_date,
                        '+1 month'
                    );

                $repeat->due_date =
                    self::shiftDate(
                        $this->due_date,
                        '+1 month'
                    );
                break;

            case 'quarterly':
                $repeat->start_date =
                    self::shiftDate(
                        $this->start_date,
                        '+3 months'
                    );

                $repeat->due_date =
                    self::shiftDate(
                        $this->due_date,
                        '+3 months'
                    );
                break;

            case 'semi_annually':
                $repeat->start_date =
                    self::shiftDate(
                        $this->start_date,
                        '+6 months'
                    );

                $repeat->due_date =
                    self::shiftDate(
                        $this->due_date,
                        '+6 months'
                    );
                break;

            case 'annually':
                $repeat->start_date =
                    self::shiftDate(
                        $this->start_date,
                        '+1 year'
                    );

                $repeat->due_date =
                    self::shiftDate(
                        $this->due_date,
                        '+1 year'
                    );
                break;

            case 'sprint':
                $sprint = new Sprint();

                $sprint->load(
                    ['start_date > NOW()'],
                    ['order' => 'start_date']
                );

                if ($sprint->id) {
                    $repeat->start_date =
                        $this->start_date
                            ? $sprint->start_date
                            : null;

                    $repeat->due_date =
                        $sprint->end_date;
                }

                break;
        }
    }

    /**
     * Log changes before saving.
     */
    protected function _saveUpdate(
        bool $notify = true
    ): Issue\Update|false {
        $f3 = \Base::instance();

        if (
            $this->id
            && (int) $this->id
                === (int) $this->parent_id
        ) {
            $this->parent_id =
                $this->_getPrev(
                    'parent_id'
                );
        }

        $update = new Issue\Update();

        $update->issue_id =
            (int) $this->id;

        $update->user_id =
            self::positiveInt(
                $f3->get('user.id')
            );

        $update->created_date =
            date('Y-m-d H:i:s');

        if ($f3->exists('update_comment')) {
            $comment =
                $f3->get('update_comment');

            if (
                is_object($comment)
                && isset($comment->id)
            ) {
                $update->comment_id =
                    (int) $comment->id;

                $update->notify =
                    (int) $notify;
            }
        }

        if (!isset($update->notify)) {
            $update->notify = 0;
        }

        $update->save();

        if (
            $this->hours_remaining
            && !$this->hours_total
            && !$this->_getPrev(
                'hours_remaining'
            )
            && !$this->_getPrev(
                'hours_total'
            )
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

        if (
            $this->closed_date
            && $this->repeat_cycle
        ) {
            $this->repeat($notify);
            $this->repeat_cycle = null;
        }

        $updated = 0;
        $importantChanges = 0;

        foreach (
            $this->fields as $key => $field
        ) {
            if (
                empty($field['changed'])
                || rtrim(
                    (string) (
                        $field['value'] ?? ''
                    )
                ) === rtrim(
                    (string) (
                        $this->_getPrev($key)
                        ?? ''
                    )
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
                $this->_getPrev($key);

            $updateField->new_value =
                $field['value'];

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
     * Save issue.
     */
    public function save(bool $notify = true): Issue
    {
        $f3 = \Base::instance();

        $this->normalizeBeforeSave();

        if (
            $f3->get('security.block_ccs')
        ) {
            $this->description =
                self::maskSensitiveNumbers(
                    (string) $this->description
                );
        }

        $issue = null;
        $update = false;

        if ($this->query) {
            $update =
                $this->_saveUpdate($notify);

            $issue = parent::save();

            if (
                $notify
                && $update
                && $update->id
                && $update->notify
            ) {
                \Helper\Notification::instance()
                    ->issue_update(
                        (int) $this->id,
                        (int) $update->id
                    );
            }
        } elseif (
            !$this->closed_date
            && $this->status
        ) {
            $status =
                new Issue\Status();

            $status->load(
                (int) $this->status
            );

            if (
                $status->id
                && $status->closed
            ) {
                $this->closed_date =
                    date('Y-m-d H:i:s');
            }
        }

        if ($issue === null) {
            $issue = parent::save();
        }

        $this->saveTags();

        return $issue;
    }

    /**
     * Normalize data immediately before persistence.
     */
    private function normalizeBeforeSave(): void
    {
        if ($this->sprint_id === 0) {
            $this->sprint_id = null;
        }

        $this->name =
            trim((string) $this->name);

        $this->description =
            self::clean(
                (string) $this->description
            );

        if ($this->due_date) {
            $this->due_date =
                self::normalizeDate(
                    $this->due_date
                );
        }

        if ($this->start_date) {
            $this->start_date =
                self::normalizeDate(
                    $this->start_date
                );
        }

        $this->repeat_cycle =
            self::normalizeRepeatCycle(
                $this->repeat_cycle
            );

        $this->parent_id =
            self::nullablePositiveInt(
                $this->parent_id
            );

        $this->owner_id =
            self::nullablePositiveInt(
                $this->owner_id
            );

        $this->sprint_id =
            self::nullablePositiveInt(
                $this->sprint_id
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
    }

    /**
     * Save tags found in description.
     */
    public function saveTags(): Issue
    {
        $tag = new Issue\Tag();

        if ($this->id) {
            $tag->deleteByIssueId(
                (int) $this->id
            );
        }

        if ($this->deleted_date) {
            return $this;
        }

        $description =
            (string) $this->description;

        if ($description === '') {
            return $this;
        }

        $count = preg_match_all(
            '/(?<=[^a-z\/&]#|^#)[a-z][a-z0-9_-]*[a-z0-9]+(?=[^a-z\/]|$)/i',
            $description,
            $matches
        );

        if (!$count) {
            return $this;
        }

        $saved = [];

        foreach ($matches[0] as $match) {
            $normalized =
                preg_replace(
                    '/[_-]+/',
                    '-',
                    ltrim(
                        (string) $match,
                        '#'
                    )
                );

            $normalized =
                trim(
                    (string) $normalized
                );

            if (
                $normalized === ''
                || isset($saved[$normalized])
            ) {
                continue;
            }

            $saved[$normalized] = true;

            $tag->reset();
            $tag->tag = $normalized;
            $tag->issue_id =
                (int) $this->id;

            $tag->save();
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
            throw new \Exception(
                'Cannot duplicate an issue that is not yet saved.'
            );
        }

        $newIssue =
            $this->duplicateIssue(
                $this,
                null,
                true
            );

        if ($recursive) {
            $this->_duplicateTree(
                (int) $this->id,
                (int) $newIssue->id
            );
        }

        return $newIssue;
    }

    /**
     * Duplicate children.
     */
    protected function _duplicateTree(
        int $id,
        int $newId
    ): Issue {
        $visited = [];

        $this->duplicateTree(
            $id,
            $newId,
            $visited,
            0
        );

        return $this;
    }

    private function duplicateTree(
        int $id,
        int $newId,
        array &$visited,
        int $depth
    ): void {
        if (
            $depth >=
                self::MAX_HIERARCHY_DEPTH
            || isset($visited[$id])
        ) {
            return;
        }

        $visited[$id] = true;

        foreach (
            $this->find([
                'parent_id = ?',
                $id,
            ]) as $child
        ) {
            if (
                !$child->id
                || $child->deleted_date
            ) {
                continue;
            }

            $newChild =
                $this->duplicateIssue(
                    $child,
                    $newId,
                    false
                );

            $this->duplicateTree(
                (int) $child->id,
                (int) $newChild->id,
                $visited,
                $depth + 1
            );
        }
    }

    private function duplicateIssue(
        Issue $source,
        ?int $parentId,
        bool $notify
    ): Issue {
        $f3 = \Base::instance();

        $source->copyto(
            'duplicating_issue'
        );

        foreach (
            [
                'id',
                'due_date',
                'hours_spent',
            ] as $field
        ) {
            $f3->clear(
                'duplicating_issue.'
                . $field
            );
        }

        $issue = new Issue();

        $issue->copyfrom(
            'duplicating_issue'
        );

        $issue->author_id =
            (int) $f3->get(
                'user.id'
            );

        $issue->hours_remaining =
            $issue->hours_total;

        $issue->created_date =
            date('Y-m-d H:i:s');

        if ($parentId !== null) {
            $issue->parent_id =
                $parentId;
        }

        $issue->save($notify);

        return $issue;
    }

    /**
     * Move child tasks to same sprint.
     */
    public function resetTaskSprints(
        bool $replaceExisting = true
    ): Issue {
        if (!$this->sprint_id) {
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
                ':sprint' =>
                    (int) $this->sprint_id,

                ':issue' =>
                    (int) $this->id,

                ':type' =>
                    (int) \Base::instance()
                        ->get(
                            'issue_type.project'
                        ),
            ]
        );

        return $this;
    }

    /**
     * Get active children.
     */
    public function getChildren(): array
    {
        if ($this->_children !== null) {
            return $this->_children;
        }

        if (!$this->id) {
            return $this->_children = [];
        }

        return $this->_children =
            $this->find([
                'parent_id = ? AND deleted_date IS NULL',
                (int) $this->id,
            ]);
    }

    /**
     * Generate hashes used by the existing change-detection protocol.
     *
     * MD5 is kept for compatibility with the existing controller/client
     * implementation. Changing it requires both sides to be migrated.
     */
    public function hashState(): array
    {
        $result = $this->cast();

        foreach (
            $result as &$value
        ) {
            $value = md5(
                (string) (
                    $value ?? ''
                )
            );
        }

        unset($value);

        return $result;
    }

    /**
     * Close issue.
     */
    public function close(): Issue
    {
        if (
            !$this->id
            || $this->closed_date
        ) {
            return $this;
        }

        $status =
            new Issue\Status();

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
     * Return this issue and all descendant IDs.
     *
     * Iterative implementation avoids uncontrolled recursion and
     * prevents circular hierarchy processing.
     */
    public function descendantIds(): array
    {
        if (!$this->id) {
            return [];
        }

        $ids = [];
        $visited = [];

        $stack = [
            [$this, 0],
        ];

        while ($stack !== []) {
            [$issue, $depth] =
                array_pop($stack);

            $id =
                (int) $issue->id;

            if (
                $id <= 0
                || isset($visited[$id])
            ) {
                continue;
            }

            $visited[$id] = true;
            $ids[] = $id;

            if (
                $depth >=
                self::MAX_HIERARCHY_DEPTH
            ) {
                continue;
            }

            foreach (
                $issue->getChildren()
                as $child
            ) {
                if (
                    !$child instanceof self
                ) {
                    continue;
                }

                $stack[] = [
                    $child,
                    $depth + 1,
                ];
            }
        }

        return $ids;
    }

    /**
     * Calculate project statistics.
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

        $visited = [];

        $stack = [
            [$this, 0],
        ];

        while ($stack !== []) {
            [$issue, $depth] =
                array_pop($stack);

            $id =
                (int) $issue->id;

            if (
                $id <= 0
                || isset($visited[$id])
            ) {
                continue;
            }

            $visited[$id] = true;

            $stats['total']++;

            if ($issue->closed_date) {
                $stats['complete']++;
            }

            $stats['hours_spent'] +=
                max(
                    0,
                    (float) (
                        $issue->hours_spent
                        ?? 0
                    )
                );

            $stats['hours_total'] +=
                max(
                    0,
                    (float) (
                        $issue->hours_total
                        ?? 0
                    )
                );

            if (
                $depth >=
                self::MAX_HIERARCHY_DEPTH
            ) {
                continue;
            }

            foreach (
                $issue->getChildren()
                as $child
            ) {
                if (
                    $child instanceof self
                ) {
                    $stack[] = [
                        $child,
                        $depth + 1,
                    ];
                }
            }
        }

        return $stats;
    }

    /**
     * Verify if user is allowed to access this issue.
     */
    public function allowAccess(
        ?\Model\User $user = null
    ): bool {
        $f3 = \Base::instance();

        if (
            !$user instanceof
                \Model\User
        ) {
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

        $userId =
            (int) $user->id;

        if (
            (int) $this->owner_id
                === $userId
            || (int) $this->author_id
                === $userId
        ) {
            return true;
        }

        $groupIds =
            \Helper\Dashboard::instance()
                ->getGroupIds();

        if (!is_array($groupIds)) {
            return false;
        }

        $groupIds =
            array_map(
                'intval',
                $groupIds
            );

        return
            $this->owner_id !== null
            && in_array(
                (int) $this->owner_id,
                $groupIds,
                true
            );
    }

    /**
     * Convert a value to a positive integer.
     */
    private static function positiveInt(
        mixed $value
    ): ?int {
        if (
            $value === null
            || $value === ''
            || is_bool($value)
        ) {
            return null;
        }

        $filtered =
            filter_var(
                $value,
                FILTER_VALIDATE_INT,
                [
                    'options' => [
                        'min_range' => 1,
                    ],
                ]
            );

        return $filtered === false
            ? null
            : $filtered;
    }

    /**
     * Convert optional ID to positive integer/null.
     */
    private static function nullablePositiveInt(
        mixed $value
    ): ?int {
        if (
            $value === null
            || $value === ''
            || $value === 0
            || $value === '0'
        ) {
            return null;
        }

        return self::positiveInt(
            $value
        );
    }

    /**
     * Validate a non-negative numeric value.
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
     * Validate and normalize a date.
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

        $value =
            trim(
                (string) $value
            );

        if ($value === '') {
            return null;
        }

        $date =
            \DateTimeImmutable::createFromFormat(
                '!Y-m-d',
                $value
            );

        $errors =
            \DateTimeImmutable::getLastErrors();

        if (
            $date !== false
            && (
                $errors === false
                || (
                    $errors['warning_count'] === 0
                    && $errors['error_count'] === 0
                )
            )
            && $date->format('Y-m-d')
                === $value
        ) {
            return $value;
        }

        $timestamp =
            strtotime($value);

        if ($timestamp === false) {
            return null;
        }

        return date(
            'Y-m-d',
            $timestamp
        );
    }

    /**
     * Validate repeat-cycle value.
     */
    private static function normalizeRepeatCycle(
        mixed $value
    ): ?string {
        if (
            !is_string($value)
            || $value === ''
        ) {
            return null;
        }

        $value = trim($value);

        return in_array(
            $value,
            self::REPEAT_CYCLES,
            true
        )
            ? $value
            : null;
    }

    /**
     * Shift date safely.
     */
    private static function shiftDate(
        mixed $date,
        string $modifier
    ): ?string {
        if (
            !is_string($date)
            || trim($date) === ''
        ) {
            return null;
        }

        $timestamp =
            strtotime(
                $date . ' ' . $modifier
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
     * Mask sequences resembling credit-card numbers.
     */
    private static function maskSensitiveNumbers(
        string $description
    ): string {
        $result = preg_replace(
            '/(?:\d{3,4}-){3}(\d{3,4})/',
            '************$1',
            $description
        );

        return $result
            ?? $description;
    }
}

