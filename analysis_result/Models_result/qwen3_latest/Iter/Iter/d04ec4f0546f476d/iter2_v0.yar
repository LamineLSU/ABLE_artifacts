rule ConditionalCheckAndExit
{
    meta:
        description = "Detects conditional checks and exit behavior in code."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }  // Call, compare, jump (conditional check)
        $pattern1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }  // Call to TerminateProcess, then jump to exit
        $pattern2 = { C1 E8 08 A8 01 75 10 }            // SHR, TEST, JNE (conditional check)

    condition:
        all of them
}