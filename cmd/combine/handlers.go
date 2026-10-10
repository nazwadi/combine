package main

import "net/http"

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{"Title": "Home"}
	if err := a.tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		a.log.Error("rendering home", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
