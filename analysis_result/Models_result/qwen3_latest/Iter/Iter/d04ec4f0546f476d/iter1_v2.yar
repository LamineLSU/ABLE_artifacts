rule CodeFlowPatterns
{
    meta:
        description = "Identifies code flow patterns involving function calls and conditional jumps."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Call to GetCurrentProcess with preceding push
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }      // Call to TerminateProcess with preceding push
        $pattern2 = { E8 ?? ?? ?? ?? 83 F8 01 74 ?? }  // EAX comparison and conditional jump

    condition:
        all of them
}