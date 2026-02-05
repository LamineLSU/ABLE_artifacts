rule Bypass_Sample
{
    meta:
        description = "Bypass ExitProcess at 00E8A1F8 using specific instruction sequences",
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    strings:
        $pattern0 = { 85 C0 8B CE E8 25 FF 15 F0 FE 00 }
        $pattern1 = { 6A B9 FF BE 8C 88 1E 34 5B FF 7F }
        $pattern2 = { A8 C7 EB D4 DD F0 FE FF 00 5E FF 7E }
    condition:
        any_of them
}