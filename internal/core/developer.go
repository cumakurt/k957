package core

const (
	DeveloperName     = "Cuma Kurt"
	DeveloperEmail    = "cumakurt@gmail.com"
	RepositoryURL     = "https://github.com/cumakurt/k957"
	DeveloperLinkedIn = "https://www.linkedin.com/in/cuma-kurt-34414917/"
)

type DeveloperDetails struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	Repository string `json:"repository"`
	LinkedIn   string `json:"linkedin"`
}

func DeveloperInfo() DeveloperDetails {
	return DeveloperDetails{DeveloperName, DeveloperEmail, RepositoryURL, DeveloperLinkedIn}
}

// Software credits are separate from the examiner's identity and conclusions.
const developerHTML = `<p class="software-credit">Software developer: ` + DeveloperName + ` · <a href="mailto:` + DeveloperEmail + `">` + DeveloperEmail + `</a><br><a href="` + RepositoryURL + `">Project repository</a> · <a href="` + DeveloperLinkedIn + `">LinkedIn</a></p>`

func developerDocumentRows() []documentParagraph {
	return []documentParagraph{
		{"Software developer: " + DeveloperName, false},
		{"Contact: " + DeveloperEmail, false},
		{"Repository: " + RepositoryURL, false},
		{"LinkedIn: " + DeveloperLinkedIn, false},
	}
}
