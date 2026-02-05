rule Bypass_Sample
{
    meta:
        description = "Evasion bypass via JZ/ZF or address-relative jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 B4 65 00 41 B4 86 00 41 B8 D3 00 41 B8 D9 }
        $pattern1 = { 00 41 B4 57 00 41 C2 A8 }
        $pattern2 = { 00 41 B4 57 00 41 C3 6A 00 41 D0 3C }

    condition:
        any of them
}