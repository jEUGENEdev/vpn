on run argv
    set resources to item 1 of argv
    set iconFile to POSIX file (resources & "/set.icns")
    set actionLabel to "Установить"
    try
        do shell script "test -d /Applications/Сеть.app -o -d /Applications/LineVPN.app -o -d '/Library/Application Support/LineVPN'"
        set actionLabel to "Обновить"
    end try
    try
        set choice to button returned of (display dialog "Установка, обновление и удаление приложения «Сеть»." & return & return & "При обновлении профиль, вход и правила сохраняются." with title "Установщик «Сеть»" buttons {"Отмена", "Удалить", actionLabel} default button actionLabel cancel button "Отмена" with icon iconFile)
        set operation to "install"
        if choice is "Удалить" then
            display dialog "Удалить приложение и фоновую службу «Сеть»?" & return & return & "Прямое подключение будет восстановлено. Профиль и правила останутся на этом Mac для повторной установки." with title "Удаление «Сеть»" buttons {"Отмена", "Удалить"} default button "Отмена" cancel button "Отмена" with icon caution
            set operation to "uninstall"
        end if
        with timeout of 1800 seconds
            do shell script "/bin/bash " & quoted form of (resources & "/manage.sh") & " " & quoted form of operation with administrator privileges
        end timeout
        if operation is "install" then
            display dialog "Приложение «Сеть» установлено. Профиль и правила сохранены." with title "Готово" buttons {"Закрыть", "Открыть «Сеть»"} default button "Открыть «Сеть»" with icon iconFile
            if button returned of result is "Открыть «Сеть»" then do shell script "/usr/bin/open /Applications/Сеть.app"
        else
            display dialog "Приложение «Сеть» удалено. Прямое подключение восстановлено. Профиль и правила сохранены." with title "Готово" buttons {"Закрыть"} default button "Закрыть" with icon iconFile
        end if
    on error messageText number errorNumber
        if errorNumber is not -128 then
            display dialog "Операция не завершена." & return & return & messageText & return & return & "Повторите запуск установщика. При ошибке остановки службы сначала перезагрузите Mac." with title "Установщик «Сеть»" buttons {"Закрыть"} default button "Закрыть" with icon stop
        end if
    end try
end run
