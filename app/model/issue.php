<?php

namespace Model;

class Issue extends \Model
{
    private const MAX_HIERARCHY_NODES = 5000;

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

    public static function create(array $data, bool $notify = true): static
    {
        $data = self::normalizeInput($data);

        if (empty($data['author_id'])) {
            $userId = self::positiveInt(
                \Base::instance()->get('user.id')
            );

            if ($userId === null) {
                throw new \InvalidArgumentException(
                    'A valid author is required.'
                );
            }

            $data['author_id'] = $userId;
        }

        if (empty($data['name'])) {
            throw new \InvalidArgumentException(
                'Issue name is required.'
            );
        }

        if (
            empty($data['type_id'])
            || empty($data['status'])
        ) {
            throw new \InvalidArgumentException(
                'Invalid issue type or status.'
            );
        }

        if (
            !empty($data['parent_id'])
            && (int) $data['parent_id']
                === (int) ($data['id'] ?? 0)
        ) {
            throw new \InvalidArgumentException(
                'An issue cannot be its own parent.'
            );
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

        unset($data['due_date_sprint']);

        /** @var static $issue */
        $issue = parent::create($data);

        if ($notify && $issue->id) {
            \Helper\Notification::instance()
                ->issue_create((int) $issue->id);
        }

        return $issue;
    }

    private static function normalizeInput(array $data): array
    {
        if (array_key_exists('hours', $data)) {
            $hours = self::nonNegativeFloat(
                $data['hours']
            );

            $data['hours_total'] = $hours;
            $data['hours_remaining'] = $hours;

            unset($data['hours']);
        }

        foreach (
            [
                'type_id',
                'status',
                'author_id',
                'priority',
            ] as $field
        ) {
            if (!array_key_exists($field, $data)) {
                continue;
            }

            $value = self::positiveInt(
                $data[$field]
            );

            if ($value === null) {
                throw new \InvalidArgumentException(
                    'Invalid numeric field.'
                );
            }

            $data[$field] = $value;
        }

        foreach (
            [
                'owner_id',
                'parent_id',
                'sprint_id',
            ] as $field
        ) {
            if (array_key_exists($field, $data)) {
                $data[$field] =
                    self::nullablePositiveInt(
                        $data[$field]
                    );
            }
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
                    self::nonNegativeFloat(
                        $data[$field]
                    );
            }
        }

        if (isset($data['name'])) {
            $data['name'] =
                trim((string) $data['name']);
        }

        if (isset($data['description'])) {
            $data['description'] =
                self::clean(
                    (string) $data['description']
                );
        }

        foreach (
            ['start_date', 'due_date'] as $field
        ) {
            if (
                array_key_exists($field, $data)
                && $data[$field] !== null
                && $data[$field] !== ''
            ) {
                $date = self::normalizeDate(
                    $data[$field]
                );

                if ($date === null) {
                    throw new \InvalidArgumentException(
                        'Invalid date.'
                    );
                }

                $data[$field] = $date;
            }
        }

        if (array_key_exists('repeat_cycle', $data)) {
            $data['repeat_cycle'] =
                self::normalizeRepeatCycle(
                    $data['repeat_cycle']
                );
        }

        return $data;
    }

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

        $parentId =
            self::nullablePositiveInt(
                $this->parent_id
            );

        while ($parentId !== null) {
            self::assertTraversalLimit(
                count($visited)
            );

            if (isset($visited[$parentId])) {
                throw new \RuntimeException(
                    'Circular issue hierarchy detected.'
                );
            }

            $visited[$parentId] = true;

            $issue = new Issue();
            $issue->load($parentId);

            if (!$issue->id) {
                throw new \RuntimeException(
                    'Invalid issue hierarchy.'
                );
            }

            $issues[] = $issue;

            $parentId =
                self::nullablePositiveInt(
                    $issue->parent_id
                );
        }

        return $this->_heirarchy =
            array_reverse($issues);
    }

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

        return trim($result ?? $string);
    }

    public function delete(bool $recursive = true): Issue
    {
        if (!$this->id) {
            return $this;
        }

        if (!$this->allowAccess()) {
            throw new \RuntimeException(
                'Access denied.'
            );
        }

        $this->set(
            'deleted_date',
            $this->deleted_date
                ?: date('Y-m-d H:i:s')
        );

        if ($recursive) {
            $this->_deleteTree();
        }

        return $this->save(false);
    }

    protected function _deleteTree(): Issue
    {
        $visited = [];
        $stack = [$this];

        while ($stack !== []) {
            self::assertTraversalLimit(
                count($visited)
            );

            /** @var Issue $current */
            $current = array_pop($stack);

            $id = (int) $current->id;

            if (
                $id <= 0
                || isset($visited[$id])
            ) {
                continue;
            }

            $visited[$id] = true;

            foreach (
                $current->find([
                    'parent_id = ?',
                    $id,
                ]) as $child
            ) {
                if (!$child instanceof self) {
                    continue;
                }

                $childId = (int) $child->id;

                if (
                    $childId <= 0
                    || isset($visited[$childId])
                ) {
                    continue;
                }

                $child->set(
                    'deleted_date',
                    $child->deleted_date
                        ?: date('Y-m-d H:i:s')
                );

                $child->save(false);

                $stack[] = $child;
            }
        }

        return $this;
    }

    public function restore(bool $recursive = true): Issue
    {
        if (!$this->id) {
            return $this;
        }

        if (!$this->allowAccess()) {
            throw new \RuntimeException(
                'Access denied.'
            );
        }

        $this->set('deleted_date', null);

        if ($recursive) {
            $this->_restoreTree();
        }

        return $this->save(false);
    }

    protected function _restoreTree(): Issue
    {
        $visited = [];
        $stack = [$this];

        while ($stack !== []) {
            self::assertTraversalLimit(
                count($visited)
            );

            /** @var Issue $current */
            $current = array_pop($stack);

            $id = (int) $current->id;

            if (
                $id <= 0
                || isset($visited[$id])
            ) {
                continue;
            }

            $visited[$id] = true;

            foreach (
                $current->find([
                    'parent_id = ? AND deleted_date IS NOT NULL',
                    $id,
                ]) as $child
            ) {
                if (!$child instanceof self) {
                    continue;
                }

                $childId = (int) $child->id;

                if (
                    $childId <= 0
                    || isset($visited[$childId])
                ) {
                    continue;
                }

                $child->set(
                    'deleted_date',
                    null
                );

                $child->save(false);

                $stack[] = $child;
            }
        }

        return $this;
    }

    public function repeat(bool $notify = true): Issue
    {
        if (
            !$this->id
            || !$this->allowAccess()
        ) {
            throw new \RuntimeException(
                'Access denied.'
            );
        }

        $repeat = new Issue();

        $repeat->name =
            trim((string) $this->name);

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
            self::nonNegativeFloat(
                $this->hours_total
            );

        $repeat->hours_remaining =
            $repeat->hours_total;

        $repeat->created_date =
            date('Y-m-d H:i:s');

        $this->applyRepeatDates(
            $repeat
        );

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
                ['order' => 'start_date']
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

    private function applyRepeatDates(
        Issue $repeat
    ): void {
        $intervals = [
            'daily' => '+1 day',
            'weekly' => '+1 week',
            'monthly' => '+1 month',
            'quarterly' => '+3 months',
            'semi_annually' => '+6 months',
            'annually' => '+1 year',
        ];

        if (
            isset(
                $intervals[
                    $repeat->repeat_cycle
                ]
            )
        ) {
            $modifier =
                $intervals[
                    $repeat->repeat_cycle
                ];

            $repeat->start_date =
                $this->start_date
                    ? self::shiftDate(
                        $this->start_date,
                        $modifier
                    )
                    : null;

            $repeat->due_date =
                self::shiftDate(
                    $this->due_date,
                    $modifier
                );

            return;
        }

        if (
            $repeat->repeat_cycle !== 'sprint'
        ) {
            return;
        }

        $sprint = new Sprint();

        $sprint->load(
            ['start_date > NOW()'],
            ['order' => 'start_date']
        );

        if (!$sprint->id) {
            return;
        }

        $repeat->start_date =
            $this->start_date
                ? $sprint->start_date
                : null;

        $repeat->due_date =
            $sprint->end_date;
    }

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
                $this->_getPrev('parent_id');
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

        $update->notify = 0;

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

        $update->save();

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
            $this->fields
            as $key => $field
        ) {
            if (empty($field['changed'])) {
                continue;
            }

            $oldValue =
                $this->_getPrev($key);

            $newValue =
                $field['value'] ?? null;

            if (
                rtrim(
                    (string) ($newValue ?? '')
                ) ===
                rtrim(
                    (string) ($oldValue ?? '')
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

    public function save(
        bool $notify = true
    ): Issue {
        if (
            $this->query
            && !$this->allowAccess()
        ) {
            throw new \RuntimeException(
                'Access denied.'
            );
        }

        $f3 = \Base::instance();

        $this->normalizeBeforeSave();

        if (
            $f3->get(
                'security.block_ccs'
            )
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
                self::requiredDate(
                    $this->due_date
                );
        }

        if ($this->start_date) {
            $this->start_date =
                self::requiredDate(
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
            self::nonNegativeFloat(
                $this->hours_total
            );

        $this->hours_remaining =
            self::nonNegativeFloat(
                $this->hours_remaining
            );

        $this->hours_spent =
            self::nonNegativeFloat(
                $this->hours_spent
            );
    }

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
            || !$this->description
        ) {
            return $this;
        }

        $count = preg_match_all(
            '/(?<=[^a-z\/&]#|^#)[a-z][a-z0-9_-]*[a-z0-9]+(?=[^a-z\/]|$)/i',
            (string) $this->description,
            $matches
        );

        if (!$count) {
            return $this;
        }

        $saved = [];

        foreach (
            $matches[0] as $match
        ) {
            $value = preg_replace(
                '/[_-]+/',
                '-',
                ltrim(
                    (string) $match,
                    '#'
                )
            );

            $value =
                trim((string) $value);

            if (
                $value === ''
                || isset($saved[$value])
            ) {
                continue;
            }

            $saved[$value] = true;

            $tag->reset();
            $tag->tag = $value;
            $tag->issue_id =
                (int) $this->id;

            $tag->save();
        }

        return $this;
    }

    public function duplicate(
        bool $recursive = true
    ): Issue {
        if (!$this->id) {
            throw new \RuntimeException(
                'Cannot duplicate an unsaved issue.'
            );
        }

        if (!$this->allowAccess()) {
            throw new \RuntimeException(
                'Access denied.'
            );
        }

        $newIssue =
            $this->duplicateSingle(
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

    protected function _duplicateTree(
        int $id,
        int $newId
    ): Issue {
        $queue = [
            [$id, $newId],
        ];

        $visited = [];

        while ($queue !== []) {
            self::assertTraversalLimit(
                count($visited)
            );

            [$sourceId, $targetParentId] =
                array_shift($queue);

            if (
                isset($visited[$sourceId])
            ) {
                continue;
            }

            $visited[$sourceId] = true;

            foreach (
                $this->find([
                    'parent_id = ? AND deleted_date IS NULL',
                    $sourceId,
                ]) as $child
            ) {
                if (!$child instanceof self) {
                    continue;
                }

                $newChild =
                    $this->duplicateSingle(
                        $child,
                        $targetParentId,
                        false
                    );

                $queue[] = [
                    (int) $child->id,
                    (int) $newChild->id,
                ];
            }
        }

        return $this;
    }

    private function duplicateSingle(
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

        $copy = new Issue();

        $copy->copyfrom(
            'duplicating_issue'
        );

        $copy->author_id =
            self::positiveInt(
                $f3->get('user.id')
            );

        $copy->hours_remaining =
            $copy->hours_total;

        $copy->created_date =
            date('Y-m-d H:i:s');

        if ($parentId !== null) {
            $copy->parent_id =
                $parentId;
        }

        $copy->save($notify);

        return $copy;
    }

    public function resetTaskSprints(
        bool $replaceExisting = true
    ): Issue {
        if (
            !$this->id
            || !$this->sprint_id
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
                'Access denied.'
            );
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

        return $this->save();
    }

    public function descendantIds(): array
    {
        if (!$this->id) {
            return [];
        }

        $ids = [];
        $visited = [];
        $stack = [$this];

        while ($stack !== []) {
            self::assertTraversalLimit(
                count($visited)
            );

            /** @var Issue $issue */
            $issue = array_pop($stack);

            $id = (int) $issue->id;

            if (
                $id <= 0
                || isset($visited[$id])
            ) {
                continue;
            }

            $visited[$id] = true;
            $ids[] = $id;

            foreach (
                $issue->getChildren()
                as $child
            ) {
                if (!$child instanceof self) {
                    continue;
                }

                $childId =
                    (int) $child->id;

                if (
                    $childId > 0
                    && !isset(
                        $visited[$childId]
                    )
                ) {
                    $stack[] = $child;
                }
            }
        }

        return $ids;
    }

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
        $stack = [$this];

        while ($stack !== []) {
            self::assertTraversalLimit(
                count($visited)
            );

            /** @var Issue $issue */
            $issue = array_pop($stack);

            $id = (int) $issue->id;

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

            foreach (
                $issue->getChildren()
                as $child
            ) {
                if ($child instanceof self) {
                    $stack[] = $child;
                }
            }
        }

        return $stats;
    }

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

        if (!$user->id) {
            return false;
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
            (int) $this->owner_id === $userId
            || (int) $this->author_id === $userId
        ) {
            return true;
        }

        $groupIds =
            \Helper\Dashboard::instance()
                ->getGroupIds();

        if (!is_array($groupIds)) {
            return false;
        }

        return in_array(
            (int) $this->owner_id,
            array_map(
                'intval',
                $groupIds
            ),
            true
        );
    }

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

        return self::positiveInt($value);
    }

    private static function nonNegativeFloat(
        mixed $value
    ): ?float {
        if (
            $value === null
            || $value === ''
        ) {
            return null;
        }

        if (!is_numeric($value)) {
            throw new \InvalidArgumentException(
                'Invalid numeric value.'
            );
        }

        $number = (float) $value;

        if (
            !is_finite($number)
            || $number < 0
        ) {
            throw new \InvalidArgumentException(
                'Invalid numeric value.'
            );
        }

        return $number;
    }

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
            trim((string) $value);

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

        return null;
    }

    private static function requiredDate(
        mixed $value
    ): string {
        $date =
            self::normalizeDate($value);

        if ($date === null) {
            throw new \InvalidArgumentException(
                'Invalid date.'
            );
        }

        return $date;
    }

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

    private static function shiftDate(
        mixed $date,
        string $modifier
    ): ?string {
        $date =
            self::normalizeDate($date);

        if ($date === null) {
            return null;
        }

        $timestamp =
            strtotime(
                $date . ' ' . $modifier
            );

        return $timestamp === false
            ? null
            : date(
                'Y-m-d',
                $timestamp
            );
    }

    private static function maskSensitiveNumbers(
        string $description
    ): string {
        return preg_replace(
            '/(?:\d{3,4}-){3}(\d{3,4})/',
            '************$1',
            $description
        ) ?? $description;
    }

    private static function assertTraversalLimit(
        int $processedNodes
    ): void {
        if (
            $processedNodes
            >= self::MAX_HIERARCHY_NODES
        ) {
            throw new \RuntimeException(
                'Issue hierarchy exceeds the safe processing limit.'
            );
        }
    }
}
