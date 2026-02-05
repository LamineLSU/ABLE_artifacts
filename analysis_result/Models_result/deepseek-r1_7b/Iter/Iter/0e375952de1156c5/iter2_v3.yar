rule Bypass_Sample
{
    meta:
        description = "Evasion bypass based on stack displacement and specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 74 0A 64 A0 ?? ?? ?? ?? 8B 45 53 }
        $pattern1 = { E8 C8 FF FF FF 75 08 03 C9 5A ?? 8B CE 85 C0 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}