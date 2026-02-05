rule EvasionCheck
{
    meta:
        description = "Detects evasion logic using function call and register manipulation before ExitProcess"
        cape_options = "bp0=$call_func+0,action0=skip,bp1=$load_eax+0,action1=skip,bp2=$call_exit+0,action2=skip,count=0"
    strings:
        $call_func = { E8 74 0A 00 00 }  // call to 0041EB37h
        $load_eax = { 8B 06 }             // mov eax, dword ptr [esi]
        $call_exit = { FF D0 }            // call eax (ExitProcess)
    condition:
        all of them
}