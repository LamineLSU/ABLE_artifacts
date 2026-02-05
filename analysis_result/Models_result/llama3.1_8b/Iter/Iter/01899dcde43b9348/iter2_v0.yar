rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? } // CALL_TEST_JE (Strategy A)
        $pattern1 = { 8B CE E8 ?? ?? ?? ?? } // API_CHECK (Strategy B) - look for conditional logic before exit
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 } // CMP_SETZ ( Strategy A) - specific comparison

    condition:
        any of them
}