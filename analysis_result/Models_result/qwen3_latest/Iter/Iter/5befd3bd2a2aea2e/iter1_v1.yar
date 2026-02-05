rule ExitProcess_Identifier
{
    meta:
        description = "Identifies code that calls ExitProcess or related CRT functions"
        cape_options = "bp0=$call_exitprocess+0,action0=skip,bp1=$call_crtexit+0,action1=skip,bp2=$stack_setup+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $call_exitprocess = { FF 15 AC B0 41 00 }
        $call_crtexit = { E8 C8 FF FF FF }
        $stack_setup = { 8B FF 55 8B EC }

    condition:
        all of them
}