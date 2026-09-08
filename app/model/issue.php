private const MAX_HIERARCHY_DEPTH = 100;

/**
 * Get the current issue ID and all descendant IDs.
 *
 * Prevents circular references and uncontrolled recursion.
 *
 * @return int[]
 */
public function descendantIds(): array
{
    if (!$this->id) {
        return [];
    }

    $ids = [];
    $visited = [];
    $stack = [[$this, 0]];

    while ($stack !== []) {
        [$issue, $depth] = array_pop($stack);

        $id = filter_var(
            $issue->id,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1]]
        );

        if ($id === false || isset($visited[$id])) {
            continue;
        }

        $visited[$id] = true;
        $ids[] = $id;

        if ($depth >= self::MAX_HIERARCHY_DEPTH) {
            continue;
        }

        foreach ($issue->getChildren() as $child) {
            if (!$child instanceof self) {
                continue;
            }

            $stack[] = [$child, $depth + 1];
        }
    }

    return $ids;
}
