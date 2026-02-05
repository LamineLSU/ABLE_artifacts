rule Bypass_Sample
{
    meta:
        author = "ThreatIntel"
        cape_options = "bp0=$p0+0,action0=skip,bp1=$p1+0,action1=skip,bp2=$p2+0,action2=skip,count=0"
        description = "Patterns to bypass exit process call in evasion code"

    strings:
        // Pattern 0: Push ebp+08h followed by exit call
        $p0 = { FF 75 08 E8 ?? ?? ?? ?? }

        // Pattern 1: Exit call and subsequent instructions
        $p1 = { E8 ?? ?? ?? ?? 59 FF 75 08 FF 15 ?? ?? ?? ?? }

        // Pattern 2: Prologue and exit call
        $p2 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }

    condition:
        (uint8($p0) and uint8($p1) and uint8($p2)) or
        (uint8($p0) and uint8($p1)) or
        (uint8($p0) and uint8($p2)) or
        (uint8($p1) and uint8($p2))
}