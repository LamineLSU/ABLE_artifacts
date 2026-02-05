rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? } // CALL_TEST_JE
        $pattern1 = { 3D 00 10 00 00 0F 82 } // CMP_SETZ (concrete comparison value)
        $pattern2 = { 8B 4D F8 B9 01 00 00 E8 ?? ?? ?? ?? } // VM_DETECT (CPUID-based detection)

    condition:
        any of them
}