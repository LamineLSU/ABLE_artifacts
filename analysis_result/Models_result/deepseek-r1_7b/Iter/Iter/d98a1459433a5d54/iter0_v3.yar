rule Bypass_Sample
{
    meta:
        description = "Evasion bypass using a conditional jump instruction"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 8B 4F FF 15 88 A0 24 1F }
        $pattern1 = { E8 9B 83 C4 8E 74 ?? ?? 85 C0 0F 84 ?? 8B 4F FF 15 88 A0 36 D4 }
        $pattern2 = { 6A ?? 5A 8B CE E8 9D 2E 85 C0 0F 84 ?? 8B 4F FF 15 88 A0 24 11 }

    condition:
        any of them
}