rule Bypass_Sample_Evolved
{
    meta:
        description = "[CALL_TEST_JE] evasion bypass - evolved"
        pattern_type = "CALL_TEST_JE"
        confidence = "95"
        iteration = "1"
        cape_options = "bp0=$pattern+0,action0=halt,comment=Anti-analysis check"

    strings:
        $pattern = { 85 C0 74 12 E8 ?? ?? ?? ?? }

    condition:
        $pattern
}