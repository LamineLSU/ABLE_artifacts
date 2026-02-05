rule ExampleRule
{
    meta:
        description = "Detects specific code patterns indicating potential malicious behavior"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 6A 00 E8 ?? ?? ?? ?? }  // Push EAX followed by a call to ExitProcess (offset replaced)
        $b = { 75 ?? EB ?? EB ?? }     // Conditional jump (jne) followed by two near jumps
        $c = { B9 0A 00 00 00 F7 F1 }  // MOV ECX, 0x0A000000 followed by DIV ECX
    condition:
        all of them
}