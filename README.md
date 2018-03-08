# Item Catalog
This project is a part of Udacity [Full Stack NanoDegree Program](https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004)

## Description
This project is a RESTful web application utilizing the Flask framework which accesses a SQL database that populates categories and their items. OAuth2 provides authentication for further CRUD functionality on the application. Currently OAuth2 is implemented for Google Accounts.

## Project Overview
The project has one main python module `catalog.py` which runs the flask app. An SQL database is created using `database_setup.py` module.
The Flask applications uses HTML templates in the `templates` folder to build the front-end of the application. CSS/JS/Images are stored in the `static` directory.

## Technologies Used
* Python2.7
* HTML
* Javascript
* CSS
* SQL
* OAuth for Google
* Flask Framework

## Project Setup
1. Install Vagrant and Virtual Box.
2. Download or clone the [Full-Stack NonoDegree Virtual Machine](https://github.com/udacity/fullstack-nanodegree-vm)
3. IN the `catalog` folder, replace the contents of this repository.

To run the project on local machine, install the dependencies using
```
pip install -r requirements.txt
```

### Launch Project
1. Lauch the Vagrant VM using
```vagrant up```
2. To setup the database, run the following command within the VM
```python /vagrant/catalog/databse_setup.py```
3. Run the application within the Virtual Machine
```python /vagrant/catalog/catalog.py```
4. Access and test the application by visiting [http://localhost:5000/](http://localhost:5000/)

### Json API EndPoints
This app supports following public JSON API endpoints:

* To get items from one category:
`/category/<int:category_id>/items/json`

* To get a particular item from a category: `/category/<int:category_id>/item/<int:item_id>/json`

* Get All categories: `/catalog/json`
