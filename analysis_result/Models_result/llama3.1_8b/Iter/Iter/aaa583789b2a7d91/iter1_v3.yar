rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 6E FF FF FF CA 00 41 0E 2E } // CALL_TEST_JE
        $pattern1 = { C3 83 EC 14 8B 45 FC } // API_CHECK
        $pattern2 = { 3D 00 10 00 00 0F 82 } // CMP_SETZ

    condition:
        any of them
}