rule Bypass_Sample
{
    meta:
        description: "Evasion bypass detection"
        cape_options: "bp0=$pattern0+0(bp)@0,bp1=$pattern1+0(bp)@0,bp2=$pattern2+0(bp)@0,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 C8 FF FF 8B 45 ?? }
        $pattern1 = { F2 83 C4 85 C0 0F 84 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}