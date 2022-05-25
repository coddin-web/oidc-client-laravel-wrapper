<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Helper;

final class DateTimeDiffCalculator
{
    public static function differenceInSeconds(
        \DateTimeInterface $start,
        \DateTimeInterface $end,
    ): int {
        $diff = $end->diff($start);

        $daysInSecs = ((int) $diff->format('%r%a') * 24 * 60 * 60);
        $hoursInSecs = ($diff->h * 60 * 60);
        $minsInSecs = ($diff->i * 60);

        return ($daysInSecs + $hoursInSecs + $minsInSecs + $diff->s);
    }
}
