# AlbSkills2025
Heart+ Albanian Skills 2025 Challenge - Engineering a prototype by laying the groundwork for a tool that will revolutionize healthcare systems in the future of Albania.

Data used in the software: 
Admin's Password: Admin25!
Mr.Delaware Password: Delaware1983#
Mrs.Kelly's Password: Kelly1990%
secret_key to register = 91Life_Staff_Access?!

So I started laying out the application, firstly with the database that contained the staff's data and then with the login system.
I created the login and registration options, which would allow healthcare staff to access their data securely.
To ensure the application's security, I added a secret key before login and registration, accessible only to staff and admin.
To secure the confidentiality of the data, every password is stored as a hashing algorithm that I wrote myself, making it impossible for hackers to gain access to the passwords.
Then I also added some restrictions in the Password, username, and role fields that would prevent staff from using weak credentials that can easily be hacked.
Another point for security was the session and the logs feature, which would track every action the server receives,  providing full transparency of the application to the security engineers and the SOC team.
After that, the other feature I developed was the Patient Registry that the doctors would be able to use to create new patients with their particular data, such as MRN, Name, Date of birth, Patient ID, and so on. The application would take data from the CLI and add the patient data to the database file, ensuring database reusability.
Also, another security feature would be that any other users other than doctors would be unable to create a new patient.
The other feature I included was the report upload, where the doctor or nurse can upload reports into the system, from where they are saved in the database, and then can be used to display information about the patients.
I did this by using the file path of the files that needed to be uploaded, and then the data was extracted into key points, and then was transferred to the transmission section of each patient.
The other feature was that after these files were uploaded, the algorithm detected which patient the data belonged to.
Also, I created a dashboard feature that enabled only the doctors to view patient data and recent transmissions, which was made by arranging data from the database to the CLI, providing doctors with full transparency about their patients. 
Doctors can see patient data and their Transmission.
Lastly, the search algorithm would provide doctors with the ease of usage, which could provide doctors with the search query they provided. Unfortunately, this feature is still under development. :(

