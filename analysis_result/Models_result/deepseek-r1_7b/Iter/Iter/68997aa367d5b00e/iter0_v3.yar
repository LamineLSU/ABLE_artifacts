rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? E8 F3 FF FF F1 ?? 00 00 }
        $pattern1 = { 6A ?? ?? CE 45 ?? 8B C7 FF FF FF E8 A2 FF FF FF 00 00 }
        $pattern2 = { 6A ?? 5A 8B F3 ?? E8 7F FF FF FF 00 00 }

    condition:
        any of them
}