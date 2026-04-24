rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 25 05 00 00 85 C0 } // Bypass test eax, eax at 00946188
        $pattern1 = { 8B 85 F0 FE FF FF 85 C0 0F 84 33 FD FF FF } // Bypass test eax, eax at 009461A3
        $pattern2 = { 50 FF 15 88 A0 94 00 } // Bypass call at 009461F1

    condition:
        any of them
}