rule ExitMechanism1
{
    meta:
        description = "Exit logic: push ebx followed by call to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 53 E8 ?? ?? ?? ?? } // push ebx, call [offset]
    condition:
        $a
}

rule ExitMechanism2
{
    meta:
        description = "Conditional jump to Exit logic: test eax, eax followed by je"
    strings:
        $b = { 85 C0 EB ?? } // test eax, eax, je [offset]
    condition:
        $b
}

rule ExitMechanism3
{
    meta:
        description = "Cleanup before exit: call to CloseHandle"
    strings:
        $c = { E8 ?? ?? ?? ?? } // call [offset]
    condition:
        $c
}