rule ConditionalJumpToExit
{
    meta:
        description = "Detects a conditional jump to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 85 C0 }          // test eax, eax
        $b = { 75 07 }          // jne 0x07 (relative jump)
        $c = { FF 15 ?? ?? ?? ?? } // call to ExitProcess (with address wildcards)
    condition:
        all of them
}