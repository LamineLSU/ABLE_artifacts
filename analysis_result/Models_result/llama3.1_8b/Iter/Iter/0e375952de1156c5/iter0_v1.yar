rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:

    condition:
        any of them
}

$pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? }
$pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? FF 15 AC B0 41 00 }
$pattern2 = { E8 0D 0C 00 00 33 DB BA 21 05 00 00 53 }