rule Bypass_Sample_Evolved
{
    meta:
        description = "[CALL_TEST_JE] evasion bypass - evolved"
        pattern_type = "CALL_TEST_JE"
        confidence = "95"
        iteration = "2"
        cape_options = "bp0=$pattern+0,action0=skip,count=0"

    strings:
        $pattern = { 53 E8 ?? ?? ?? ?? 85 C0 74 ?? }

    condition:
        $pattern
}