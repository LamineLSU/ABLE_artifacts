rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? } // API_CHECK
        $pattern1 = { 52 33 C9 89 C6 ?? ?? ?? ?? F7 D8 E8 ?? ?? ?? ?? } // CALL_TEST_JE
        $pattern2 = { 83 EC ?? ?? 3B FF 74 ?? ?? 83 C0 ?? ?? } // CMP_SETZ

    condition:
        any of them
}