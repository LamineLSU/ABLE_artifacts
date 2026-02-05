rule ExitProcess_Call
{
    meta:
        description = "Detects calls to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $a = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? } // push ebp, mov ebp, esp, push ebp+08h, call
        $b = { FF 75 08 E8 ?? ?? ?? ?? }           // push ebp+08h, call
        $c = { FF 75 08 FF 15 ?? ?? ?? ?? }        // push ebp+08h, call to memory address

    condition:
        ( $a or $b or $c ) and ( $a or $b or $c )
}