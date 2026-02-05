rule EvasionCheckAndExit
{
    meta:
        description = "Detects evasion check and exit call patterns in the trace"
        cape_options = "bp0=$test_je_call+0,action0=skip,bp1=$exit_call+0,action1=skip,bp2=$initial_check_call+0,action2=skip,count=0"
        confidence = 70

    strings:
        // Pattern 1: Test EAX, EAX followed by JE and subsequent call (10 bytes)
        $test_je_call = { 85 C0 74 0E E8 ?? ?? ?? ?? }

        // Pattern 2: Exit call to FF 15 (6 bytes)
        $exit_call = { FF 15 ?? ?? ?? ?? }

        // Pattern 3: Initial call to check function (5 bytes + 1 wildcard byte)
        $initial_check_call = { E8 43 1C 00 00 E8 }

    condition:
        $test_je_call or $exit_call or $initial_check_call
}