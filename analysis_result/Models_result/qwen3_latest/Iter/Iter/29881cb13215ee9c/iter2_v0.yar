rule Bypass_Sample_Evolved
{
    meta:
        description = "[CALL_TEST_JE] evasion bypass - evolved"
        pattern_type = "CALL_TEST_JE"
        confidence = "95"
        iteration = "2"
        cape_options = "bp0=$pattern+0x00000004,action0=skip,count=0"

    strings:
        $pattern = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        $pattern
}