rule je_to_exit
{
    meta:
        description = "Matches the jump instruction leading to ExitProcess"
        cape_options = "bp0=$je+0,action0=skip,count=0"
    strings:
        $je = { 74 ?? }
    condition:
        $je
}