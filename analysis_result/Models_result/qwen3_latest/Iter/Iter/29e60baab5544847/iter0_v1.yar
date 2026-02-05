rule ConditionalJumpAndExitProcess
{
    meta:
        description = "Detects a conditional jump based on EAX followed by a call to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $a = { 85 C0 74 ?? ?? ?? ?? }
        $b = { 50 FF 15 ?? ?? ?? ?? }

    condition:
        $a and $b
}