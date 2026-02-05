rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 BD 04 F9 FF FF 01 }  // Original: cmp dword ptr [ebp-000006FCh], 01h
        $pattern1 = { 68 13 51 40 00 E8 1D 03 00 00 } // Original: push 00405113h; call 0040245Bh
        $pattern2 = { 8D B5 5C FC FF FF E8 6B 07 00 00 } // Original: lea esi, dword ptr [ebp-000003A4h]; call 004031B6h

    condition:
        any of them
}