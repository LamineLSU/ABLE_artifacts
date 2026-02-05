rule ExitProcess_Detection
{
    meta:
        description = "Detects code that calls ExitProcess or its internal call chain"
        cape_options = "bp0=$call_exit_process+0,action0=skip,bp1=$call_crtcor+0,action1=skip,bp2=$stack_setup+0,action2=skip,count=0"

    strings:
        $call_exit_process = { FF 15 ?? ?? ?? ?? }
        $call_crtcor = { E8 ?? ?? ?? ?? }
        $stack_setup = { 8B FF 55 8B EC }

    condition:
        any of them
}