rule ConditionalCheck
{
    meta:
        description = "Identifies a conditional check involving system time, stack operations, and flag setting."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 75

    strings:
        $a = { E8 B0 C8 F9 FF 66 81 3C 24 E4 07 73 07 }  // GetSystemTime, cmp, jnc
        $b = { 73 07 6A 00 E8 D1 C7 F9 FF }           // jnc, push 0, ExitProcess
        $c = { 81 FB 01 00 00 80 0F 94 C0 }            // cmp ebx, 80000001h, sete al

    condition:
        all of ($a, $b, $c)
}