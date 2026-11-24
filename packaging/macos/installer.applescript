on run argv
    set resources to item 1 of argv
    set iconFile to POSIX file (resources & "/set.icns")
    try
        set choice to button returned of (display dialog "Установка и полное удаление приложения «Сеть»." & return & return & "Если приложение уже установлено или установка прервалась, сначала выберите «Удалить», затем «Установить». Для нового входа понадобятся профиль сервера и ключ доступа." with title "Установщик «Сеть»" buttons {"Отмена", "Удалить", "Установить"} default button "Установить" cancel button "Отмена" with icon iconFile)
        set operation to "install"
        if choice is "Удалить" then
            display dialog "Полностью удалить «Сеть»?" & return & return & "Будут удалены приложение, служба, локальный профиль, вход и настройки. Несохранённые на сервере правила будут потеряны. Прямое подключение вернётся после остановки службы. Для нового входа нужны профиль и ключ доступа." with title "Удаление «Сеть»" buttons {"Отмена", "Удалить"} default button "Отмена" cancel button "Отмена" with icon caution
            set operation to "uninstall"
        end if
        with timeout of 1800 seconds
            set operationDetails to do shell script "/bin/bash " & quoted form of (resources & "/manage.sh") & " " & quoted form of operation with administrator privileges
        end timeout
        if operation is "install" then
            display dialog "Приложение «Сеть» установлено. Фоновая служба запущена и проверена. Добавьте профиль сервера и войдите." with title "Готово" buttons {"Закрыть", "Открыть «Сеть»"} default button "Открыть «Сеть»" with icon iconFile
            if button returned of result is "Открыть «Сеть»" then do shell script "/usr/bin/open /Applications/Сеть.app"
        else
            set completionText to "Приложение «Сеть», служба и локальные данные удалены. Запустите установщик снова и выберите «Установить»."
            if operationDetails is not "" then
                display dialog completionText & return & return & operationDetails with title "Удалено с предупреждением" buttons {"Закрыть"} default button "Закрыть" with icon caution
            else
                display dialog completionText with title "Готово" buttons {"Закрыть"} default button "Закрыть" with icon iconFile
            end if
        end if
    on error messageText number errorNumber
        if errorNumber is not -128 then
            display dialog "Операция не завершена." & return & return & messageText with title "Установщик «Сеть»" buttons {"Закрыть"} default button "Закрыть" with icon stop
        end if
    end try
end run
