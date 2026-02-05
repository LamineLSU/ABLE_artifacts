rule ConditionalJumpAndRegisterTransfer
{
    meta:
        description = "Identifies a conditional jump after a test, followed by register transfer"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B 5A }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? 8B DA }
        $pattern2 = { FF 15 ?? ?? ?? ?? }
    condition:
        all of them
}