# mmap_dll_module_unloader
Что это?
В этом репозитории описан пример того, как можно "выгрузить" вручную загруженную библиотеку (manual map) с учетом наличия сопоставленных также вручную static tls.
Проблема заключается в том, что вручную загруженная библиотека не регистрируется в структурах PEB и поэтому вызов FreeLibraryAndWxitThread не принесет никакого результата.
Для того, чтобы выгрузить библиотеку нужно удалить запись TLS модуля из списка TLS Entry 
(быть может можно сделать это проще, но я другого способа не нашел), завершить все работающие потоки модуля, 
выделить память под функцию, что будет выполнять роль "выгружатора" и освободить память, чтобы была выделена под модуль
