rule ConditionalJumpsAndCall
{
    meta:
        description = "Identifies conditional jumps and a call to ExitProcess"
        cape_options = "bp0=$cmp_je+0,action0=skip,bp1=$test_jne+0,action1=skip,bp2=$call_exit+0,action2=skip,count=0"
    
    strings:
        $cmp_je = { 83 F8 01 74 20 FF 75 08 }  // CMP + JE + PUSH
        $test_jne = { A8 01 75 10 FF 75 08 }   // TEST + JNE + PUSH
        $call_exit = { FF 15 ?? ?? ?? ?? }     // CALL with wildcards for address
    
    condition:
        all of them
}