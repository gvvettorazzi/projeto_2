<?php

namespace Model;

class Issue extends \Model
{
    private const MAX_HIERARCHY_DEPTH = 100;

    protected $_table_name = "issue";
    protected $_heirarchy;
    protected $_children;

    protected static $requiredFields = [
        "type_id",
        "status",
        "name",
        "author_id",
    ];

    public static function create(array $data, bool $notify = true): static
    {
        if (isset($data["hours"])) {
            $data["hours_total"] = $data["hours"];
            $data["hours_remaining"] = $data["hours"];
            unset($data["hours"]);
        }

        if (!empty($data["due_date"])) {
            if (
                preg_match(
                    "/\\d{4}(-\\d{2}){2}/",
                    (string) $data["due_date"]
                ) === false
            ) {
                $data["due_date"] = date(
                    "Y-m-d",
                    strtotime((string) $data["due_date"])
                );
            }

            if (
                empty($data["sprint_id"])
                && !empty($data["due_date_sprint"])
            ) {
                $sprint = new Sprint();
                $sprint->load([
                    "DATE(?) BETWEEN start_date AND end_date",
                    $data["due_date"],
                ]);

                $data["sprint_id"] = $sprint->id;
            }
        }

        if (
            empty($data["author_id"])
            && $userId = \Base::instance()->get("user.id")
        ) {
            $data["author_id"] = $userId;
        }

        $item = parent::create($data);

        if ($notify) {
            \Helper\Notification::instance()
                ->issue_create($item->id);
        }

        return $item;
    }

    public function getAncestors(): array
    {
        if ($this->_heirarchy !== null) {
            return $this->_heirarchy;
        }

        $issues = [$this];
        $issueIds = [$this->id];
        $parentId = $this->parent_id;

        while ($parentId) {
            if (in_array($parentId, $issueIds)) {
                \Base::instance()->set(
                    "error",
                    "Issue parent tree contains an infinite loop. "
                    . "Issue {$parentId} is the first point of recursion."
                );

                break;
            }

            $issue = new Issue();
            $issue->load($parentId);

            if (!$issue->id) {
                \Base::instance()->set(
                    "error",
                    "Issue parent tree references an invalid parent."
                );

                break;
            }

            $issues[] = $issue;
            $issueIds[] = $issue->id;
            $parentId = $issue->parent_id;
        }

        return $this->_heirarchy = array_reverse($issues);
    }

    public static function clean(string $string): string
    {
        return preg_replace(
            '/(?:(?:\r\n|\r|\n)\s*){2}/s',
            "\n\n",
            str_replace("\r\n", "\n", $string)
        );
    }

    public function delete(bool $recursive = true): Issue
    {
        if (!$this->deleted_date) {
            $this->set(
                "deleted_date",
                date("Y-m-d H:i:s")
            );
        }

        if ($recursive) {
            $this->_deleteTree();
        }

        return $this->save(false);
    }

    protected function _deleteTree(): Issue
    {
        foreach (
            $this->find([
                "parent_id = ?",
                $this->id,
            ]) as $child
        ) {
            $child->delete();
        }

        return $this;
    }

    public function restore(bool $recursive = true): Issue
    {
        $this->set("deleted_date", null);

        if ($recursive) {
            $this->_restoreTree();
        }

        return $this->save(false);
    }

    protected function _restoreTree(): Issue
    {
        foreach (
            $this->find([
                "parent_id = ? AND deleted_date IS NOT NULL",
                $this->id,
            ]) as $child
        ) {
            $child->restore();
        }

        return $this;
    }

    public function repeat(bool $notify = true): Issue
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
        $repeatIssue->created_date = date("Y-m-d H:i:s");

        switch ($repeatIssue->repeat_cycle) {
            case "daily":
                $repeatIssue->start_date = $this->start_date
                    ? date("Y-m-d", strtotime("tomorrow"))
                    : null;

                $repeatIssue->due_date =
                    date("Y-m-d", strtotime("tomorrow"));
                break;

            case "weekly":
                $repeatIssue->start_date = $this->start_date
                    ? date(
                        "Y-m-d",
                        strtotime($this->start_date . " +1 week")
                    )
                    : null;

                $repeatIssue->due_date = date(
                    "Y-m-d",
                    strtotime($this->due_date . " +1 week")
                );
                break;

            case "monthly":
                $repeatIssue->start_date = $this->start_date
                    ? date(
                        "Y-m-d",
                        strtotime($this->start_date . " +1 month")
                    )
                    : null;

                $repeatIssue->due_date = date(
                    "Y-m-d",
                    strtotime($this->due_date . " +1 month")
                );
                break;

            case "quarterly":
                $repeatIssue->start_date = $this->start_date
                    ? date(
                        "Y-m-d",
                        strtotime($this->start_date . " +3 months")
                    )
                    : null;

                $repeatIssue->due_date = date(
                    "Y-m-d",
                    strtotime($this->due_date . " +3 months")
                );
                break;

            case "semi_annually":
                $repeatIssue->start_date = $this->start_date
                    ? date(
                        "Y-m-d",
                        strtotime($this->start_date . " +6 months")
                    )
                    : null;

                $repeatIssue->due_date = date(
                    "Y-m-d",
                    strtotime($this->due_date . " +6 months")
                );
                break;

            case "annually":
                $repeatIssue->start_date = $this->start_date
                    ? date(
                        "Y-m-d",
                        strtotime($this->start_date . " +1 year")
                    )
                    : null;

                $repeatIssue->due_date = date(
                    "Y-m-d",
                    strtotime($this->due_date . " +1 year")
                );
                break;

            case "sprint":
                $sprint = new Sprint();

                $sprint->load(
                    ["start_date > NOW()"],
                    ["order" => "start_date"]
                );

                $repeatIssue->start_date = $this->start_date
                    ? $sprint->start_date
                    : null;

                $repeatIssue->due_date = $sprint->end_date;
                break;

            default:
                $repeatIssue->repeat_cycle = "none";
        }

        if ($this->sprint_id && $repeatIssue->due_date) {
            $sprint = new Sprint();

            $sprint->load(
                [
                    "end_date >= ? AND start_date <= ?",
                    $repeatIssue->due_date,
                    $repeatIssue->due_date,
                ],
                ["order" => "start_date"]
            );

            $repeatIssue->sprint_id = $sprint->id;
        }

        $repeatIssue->save();

        if ($notify) {
            \Helper\Notification::instance()
                ->issue_create($repeatIssue->id);
        }

        return $repeatIssue;
    }

    protected function _saveUpdate(bool $notify = true): Issue\Update
    {
        $f3 = \Base::instance();

        if ($this->id == $this->parent_id) {
            $this->parent_id =
                $this->_getPrev("parent_id");
        }

        $update = new Issue\Update();

        $update->issue_id = $this->id;
        $update->user_id = $f3->get("user.id");
        $update->created_date = date("Y-m-d H:i:s");

        if ($f3->exists("update_comment")) {
            $update->comment_id =
                $f3->get("update_comment")->id;

            $update->notify = (int) $notify;
        } else {
            $update->notify = 0;
        }

        $update->save();

        if (
            $this->hours_remaining
            && !$this->hours_total
            && !$this->_getPrev("hours_remaining")
            && !$this->_getPrev("hours_total")
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

        $importantFields = [
            "status",
            "name",
            "description",
            "owner_id",
            "priority",
            "due_date",
        ];

        foreach ($this->fields as $key => $field) {
            if (
                !$field["changed"]
                || rtrim($field["value"] ?? "")
                    === rtrim($this->_getPrev($key) ?? "")
            ) {
                continue;
            }

            $updateField =
                new Issue\Update\Field();

            $updateField->issue_update_id =
                $update->id;

            $updateField->field = $key;
            $updateField->old_value =
                $this->_getPrev($key);

            $updateField->new_value =
                $field["value"];

            $updateField->save();

            $updated++;

            if ($key === "sprint_id") {
                $this->resetTaskSprints();
            }

            if (
                in_array(
                    $key,
                    $importantFields,
                    true
                )
            ) {
                $importantChanges++;
            }
        }

        if ($updated === 0) {
            $update->delete();
        }

        if (
            $notify
            && $importantChanges > 0
            && $update->id
        ) {
            $update->notify = 1;
            $update->save();
        }

        return $update->id
            ? $update
            : false;
    }

    public function save(bool $notify = true): Issue
    {
        $f3 = \Base::instance();

        if ($this->sprint_id === 0) {
            $this->set(
                "sprint_id",
                null
            );
        }

        if (
            $f3->get("security.block_ccs")
            && preg_match(
                "/(\\d{3,4}-){3}\\d{3,4}/",
                $this->description
            )
        ) {
            $this->set(
                "description",
                preg_replace(
                    "/(\\d{3,4}-){3}(\\d{3,4})/",
                    "************$2",
                    $this->description
                )
            );
        }

        $this->due_date = $this->due_date
            ? date(
                "Y-m-d",
                strtotime($this->due_date)
            )
            : null;

        $this->start_date = $this->start_date
            ? date(
                "Y-m-d",
                strtotime($this->start_date)
            )
            : null;

        if (
            !in_array(
                $this->repeat_cycle,
                [
                    "daily",
                    "weekly",
                    "monthly",
                    "quarterly",
                    "semi_annually",
                    "annually",
                    "sprint",
                ],
                true
            )
        ) {
            $this->repeat_cycle = null;
        }

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
                        $this->id,
                        $update->id
                    );
            }
        } elseif (
            !$this->closed_date
            && $this->status
        ) {
            $status = new Issue\Status();

            $status->load($this->status);

            if ($status->closed) {
                $this->closed_date =
                    date("Y-m-d H:i:s");
            }
        }

        $return =
            empty($issue)
                ? parent::save()
                : $issue;

        $this->saveTags();

        return $return;
    }

    public function saveTags(): Issue
    {
        $tag = new Issue\Tag();

        if ($this->id) {
            $tag->deleteByIssueId(
                $this->id
            );
        }

        if ($this->deleted_date) {
            return $this;
        }

        $count = preg_match_all(
            "/(?<=[^a-z\\/&]#|^#)[a-z][a-z0-9_-]*[a-z0-9]+(?=[^a-z\\/]|$)/i",
            $this->description,
            $matches
        );

        if (!$count) {
            return $this;
        }

        foreach ($matches[0] as $match) {
            $tag->reset();

            $tag->tag = preg_replace(
                "/[_-]+/",
                "-",
                ltrim($match, "#")
            );

            $tag->issue_id = $this->id;
            $tag->save();
        }

        return $this;
    }

    public function duplicate(
        bool $recursive = true
    ): Issue {
        if (!$this->id) {
            throw new \Exception(
                "Cannot duplicate an issue that is not yet saved."
            );
        }

        $f3 = \Base::instance();

        $this->copyto(
            "duplicating_issue"
        );

        $f3->clear(
            "duplicating_issue.id"
        );

        $f3->clear(
            "duplicating_issue.due_date"
        );

        $f3->clear(
            "duplicating_issue.hours_spent"
        );

        $newIssue = new Issue();

        $newIssue->copyfrom(
            "duplicating_issue"
        );

        $newIssue->author_id =
            $f3->get("user.id");

        $newIssue->hours_remaining =
            $newIssue->hours_total;

        $newIssue->created_date =
            date("Y-m-d H:i:s");

        $newIssue->save();

        if ($recursive) {
            $this->_duplicateTree(
                $this->id,
                $newIssue->id
            );
        }

        return $newIssue;
    }

    protected function _duplicateTree(
        int $id,
        int $newId
    ): Issue {
        $children = $this->find([
            "parent_id = ?",
            $id,
        ]);

        if (!$children) {
            return $this;
        }

        $f3 = \Base::instance();

        foreach ($children as $child) {
            if ($child->deleted_date) {
                continue;
            }

            $child->copyto(
                "duplicating_issue"
            );

            $f3->clear(
                "duplicating_issue.id"
            );

            $f3->clear(
                "duplicating_issue.due_date"
            );

            $f3->clear(
                "duplicating_issue.hours_spent"
            );

            $newChild = new Issue();

            $newChild->copyfrom(
                "duplicating_issue"
            );

            $newChild->author_id =
                $f3->get("user.id");

            $newChild->hours_remaining =
                $newChild->hours_total;

            $newChild->parent_id =
                $newId;

            $newChild->created_date =
                date("Y-m-d H:i:s");

            $newChild->save(false);

            $this->_duplicateTree(
                $child->id,
                $newChild->id
            );
        }

        return $this;
    }

    public function resetTaskSprints(
        bool $replaceExisting = true
    ): Issue {
        if (!$this->sprint_id) {
            return $this;
        }

        $f3 = \Base::instance();

        $query =
            "UPDATE issue "
            . "SET sprint_id = :sprint "
            . "WHERE parent_id = :issue "
            . "AND type_id != :type";

        if ($replaceExisting) {
            $query .=
                " AND sprint_id IS NULL";
        }

        $this->db->exec(
            $query,
            [
                ":sprint" =>
                    $this->sprint_id,

                ":issue" =>
                    $this->id,

                ":type" =>
                    $f3->get(
                        "issue_type.project"
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

        return $this->_children =
            $this->find([
                "parent_id = ? "
                . "AND deleted_date IS NULL",
                $this->id,
            ]);
    }

    public function hashState(): array
    {
        $result = $this->cast();

        foreach ($result as &$value) {
            $value = md5(
                (string) ($value ?? "")
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

        $status = new Issue\Status();

        $status->load([
            "closed = ?",
            1,
        ]);

        if (!$status->id) {
            return $this;
        }

        $this->status = $status->id;

        $this->closed_date =
            date("Y-m-d H:i:s");

        $this->save();

        return $this;
    }

    public function descendantIds(): array
    {
        $ids = [];
        $seen = [];

        $stack = [
            [$this, 0],
        ];

        while ($stack) {
            [$issue, $depth] =
                array_pop($stack);

            $id = (int) $issue->id;

            if (
                $id <= 0
                || isset($seen[$id])
            ) {
                continue;
            }

            $seen[$id] = true;
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
                $stack[] = [
                    $child,
                    $depth + 1,
                ];
            }
        }

        return $ids;
    }

    public function projectStats(): array
    {
        $stats = [
            "total" => 0,
            "complete" => 0,
            "hours_spent" => 0,
            "hours_total" => 0,
        ];

        $seen = [];

        $stack = [
            [$this, 0],
        ];

        while ($stack) {
            [$issue, $depth] =
                array_pop($stack);

            $id = (int) $issue->id;

            if (
                $id <= 0
                || isset($seen[$id])
            ) {
                continue;
            }

            $seen[$id] = true;

            $stats["total"]++;

            $stats["complete"] +=
                $issue->closed_date
                    ? 1
                    : 0;

            $stats["hours_spent"] +=
                max(
                    0,
                    (float) $issue->hours_spent
                );

            $stats["hours_total"] +=
                max(
                    0,
                    (float) $issue->hours_total
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
                $stack[] = [
                    $child,
                    $depth + 1,
                ];
            }
        }

        return $stats;
    }

    public function allowAccess(
        ?\Model\User $user = null
    ): bool {
        $f3 = \Base::instance();

        if (
            !$user instanceof
                \Model\User
        ) {
            $user =
                $f3->get("user_obj");
        }

        if (
            !$user instanceof
                \Model\User
        ) {
            return false;
        }

        if ($user->role === "admin") {
            return true;
        }

        if ($this->deleted_date) {
            return false;
        }

        if (
            !$f3->get(
                "security.restrict_access"
            )
        ) {
            return true;
        }

        $groupIds =
            \Helper\Dashboard::instance()
                ->getGroupIds();

        return
            (int) $this->owner_id
                === (int) $user->id
            || (int) $this->author_id
                === (int) $user->id
            || in_array(
                (int) $this->owner_id,
                array_map(
                    "intval",
                    is_array($groupIds)
                        ? $groupIds
                        : []
                ),
                true
            );
    }
}

