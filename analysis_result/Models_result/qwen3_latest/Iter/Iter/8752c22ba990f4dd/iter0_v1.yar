rule ExitProcess_Call_Patterns
{
    meta:
        author = "Security Researcher"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        description = "Detects calls to ExitProcess with contextual instructions"

    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? 59 }  // push, call, pop
        $b = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }  // pop, push, call
        $c = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // push ebp, mov ebp, push, call

    condition:
        any of ($a, $b, $c)
}