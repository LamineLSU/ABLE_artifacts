rule ConditionalJumpAndFunctionCall
{
    meta:
        description = "Detects conditional jumps followed by function calls, potentially indicating control flow hijacking."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2025-04-05"
    
    strings:
        $pattern0 = { 85 C0 74 0E E8 ?? ?? ?? ?? }  // Test EAX, JZ 0x0E, Call (offset replaced)
        $pattern1 = { E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // Call (offset replaced), Call to ExitProcess (offset replaced)
        $pattern2 = { 74 0E E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // JZ 0x0E, Call (offset replaced), Call to ExitProcess (offset replaced)
    
    condition:
        all of them
}