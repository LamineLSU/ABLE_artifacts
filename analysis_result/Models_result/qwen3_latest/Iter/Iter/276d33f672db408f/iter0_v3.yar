rule MalwareExitPoint
{
    meta:
        description = "Detects the exit point of a malware that uses conditional checks and a call to ExitProcess."
        cape_options = "bp0=$cmp_byte+0,action0=skip,bp1=$jecxz+0,action1=skip,bp2=$call_exit+0,action2=skip,count=0"

    strings:
        $cmp_byte = { 8B 55 0C 80 33 4D }
        $jecxz = { 80 33 4D 0F 84 ?? ?? ?? ?? }
        $call_exit = { 83 C4 14 52 52 E8 44 09 00 00 FF D0 }

    condition:
        all of them
}