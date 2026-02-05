rule EvasionCheck
{
    meta:
        description = "Targets evasion checks and API calls in the execution flow"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { E8 F7 25 00 00 83 F8 01 74 20 } // CALL + CMP EAX, 01h + JE
        $b = { A8 01 75 10 }              // TEST AL, 01h + JNE
        $c = { FF 15 40 F1 42 00 }           // CALL TerminateProcess
    condition:
        all of ($a, $b, $c)
}