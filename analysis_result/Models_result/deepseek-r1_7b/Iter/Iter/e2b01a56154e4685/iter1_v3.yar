rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 6A 5B E8 ?? ?? }
        $pattern1 = { 85 C0 6A 5B 8B CE }
        $pattern2 = { E8 C8 FF FF 53 FF ?? ?? 00 }

    condition:
        any of them
}