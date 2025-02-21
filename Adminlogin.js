import React, { useState, useEffect } from "react";
import "./Adminlogin.css";
import axios from "axios";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faEdit } from "@fortawesome/free-solid-svg-icons";
import { faTrash } from "@fortawesome/free-solid-svg-icons";
export const Adminlogin = () => {
  // const roleData = {
  //   ASM: ["ASM1","ASM2","ASM3","ASM4","ASM5","ASM6","ASM7","ASM8"],
  //   RSM: ["RSM1", "RSM2"],
  //   STORE: ["STORE1","STORE2","STORE3","STORE4","STORE5","STORE6","STORE7","STORE8","STORE9","STORE10","STORE11","STORE12","STORE13",
  //     "STORE14","STORE15","STORE16","STORE17","STORE18","STORE19","STORE20","STORE21","STORE22","STORE23","STORE24","STORE25",
  //     "STORE26","STORE27","STORE28","STORE29","STORE30","STORE31","STORE32","STORE33","STORE34","STORE35","STORE36","STORE37",
  //     "STORE38","STORE39","STORE40",  
  //   ],
  // };

  const [role, setRole] = useState("");
  const [id, setId] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [users, setUsers] = useState([]);
  const [editUser, setEditUser] = useState([]);
  const [usedIds, setUsedIds] = useState([]); // usedIds state variable
  const [loading, setLoading] = useState(false);
  const [roles, setRoles] = useState([]); // Unique roles
  const [roleData, setRoleData] = useState({}); // Role-wise IDs

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await axios.get("http://localhost:5000/users");
      setUsers(response.data);

      // Update used IDs
      const usedIdsList = response.data.map((user) => user.user_id);
      setUsedIds(usedIdsList); // Correctly update usedIds
    } catch (error) {
      console.error("Error fetching users", error);
    }
  };

  const handleAddUser = async (e) => {
    e.preventDefault();
    if (!role || !id || !username || !email || !password) {
      alert("All fields are required");
      return;
    }
    if (!validateEmail(email)) {
      alert("Invalid Email Format!");
      return;
    }
  
    if (!validatePassword(password)) {
      alert("Password must be secure (8 characters, 1 uppercase letter, 1 lowercase letter, 1 number, 1 special character)");
      return;
    }
    const isUsernameTaken = users.some((user) => user.username === username);
    if (isUsernameTaken) {
      alert("Username already exists. Please choose another.");
      return;
    }
    
    try {
      await axios.post("http://localhost:5000/add_user", {
        role,
        id,
        username,
        email,
        password,
      });
      alert("User Added successfully");
      fetchUsers(); // Re-fetch the users to update used IDs
      setRole("");
      setId("");
      setUsername("");
      setEmail("");
      setPassword("");
    } catch (error) {
      console.error("Error adding user", error);
    }
  };

  // delete
  const handleDeleteUser = async (user_id) => {
    if (!window.confirm("Are you sure you want to delete this user?")) return;
    try {
      const response = await axios.delete(`http://localhost:5000/delete_user/${user_id}`);
      if (response.status === 200) {
        alert("User deleted successfully");
        setUsers((prevUsers) => prevUsers.filter(user => user.user_id !== user_id)); // UI Update
      } else {
        alert("Error deleting user");
      }
    } catch (error) {
      console.error("Error deleting user", error);
      alert("Server Error");
    }

  };


  const validateEmail = (email) => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
  };
  const validatePassword = (password) => {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
  };

  const sortedUsers = [...users].sort((a, b) => {
    const numA = parseInt(a.user_id.match(/\d+/)?.[0] || "0", 10);
    const numB = parseInt(b.user_id.match(/\d+/)?.[0] || "0", 10);
  
    if (a.user_id.replace(/[0-9]/g, "") === b.user_id.replace(/[0-9]/g, "")) {
      return numA - numB;
    }
    return a.user_id.localeCompare(b.user_id);
  });


  const handleEditClick = (user) => {
    setEditUser({ ...user, password: "" }); // Existing user data + Empty password field
  };

  const handleUpdateUser = async () => {
    if (loading) return;
    console.log("Sending Data:", editUser); // Debugging
    setLoading(true);
    try {
      const updatedUser = {
        username: editUser.username,
        email: editUser.email,
      };
  
      if (editUser.password && editUser.password.trim() !== "") {
        updatedUser.password = editUser.password;
      }
  
      console.log("Final Data Sent to Backend:", updatedUser); // Debugging
  
      await axios.put(`http://localhost:5000/update_user/${editUser.user_id}`, updatedUser);
      if (editUser.password) {
        //  Send Email API Call
        await axios.post(`http://localhost:5000/emailsend/${editUser.user_id}`, {
          email: editUser.email,
          password: editUser.password,
        });
      alert("Your password has been updated and email sent successfully!");
    } else {
      alert("User details updated successfully!");
    }
      setEditUser(null);
      fetchUsers();
    } catch (error) {
      console.error("Error updating user", error);
    } finally {
      setLoading(false);
    }
  };
// option is mysql connect
  useEffect(() => {
    // Fetch Unique Roles
    fetch("http://localhost:5000/api/roles")
        .then(response => response.json())
        .then(data => setRoles(data))
        .catch(error => console.error("Error fetching roles:", error));

    // Fetch Role-wise IDs
    fetch("http://localhost:5000/api/role-data")
        .then(response => response.json())
        .then(data => setRoleData(data))
        .catch(error => console.error("Error fetching role data:", error));
}, []);


  return (
    <>
      <div className="container">
        <h2>Create New User</h2>

        <div className="role-container">
          <label>Role: </label>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="">Select Role</option>
            {/* <option value="ASM">ASM</option>
            <option value="RSM">RSM</option>
            <option value="STORE">STORE</option> */}
            {roles.map((r, index) => (
                    <option key={index} value={r}>
                        {r}
                    </option>
                ))}
          </select>

          <label>ID: </label>
          <select value={id} onChange={(e) => setId(e.target.value)}>
            <option value="">Select ID</option>
            {role &&
              roleData[role]
                ?.filter((item) => !usedIds.includes(item)) // Remove used IDs
                .map((item, index) => (
                  <option key={index} value={item}>
                    {item}
                  </option>
                ))}
          </select>
        </div>

        <input
          type="text"
          name="username"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <input
          type="email"
          name="email"
          placeholder="Email" 
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <input
          type="password"
          name="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button onClick={handleAddUser}>Add User</button>
      </div>

      <div className="table">
        <table border={1}>
          <thead>
            <tr>
              <th>Role</th>
              <th>Code</th>
              <th>Username</th>
              <th>Email</th>
              <th>Password</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {sortedUsers.map((user, index) => (
              <tr key={index}>
                <td>{user.role}</td>
                <td>{user.user_id}</td>
                <td>{user.username}</td>
                <td>{user.email}</td>
                <td style={{ position: "relative" }}>******** <FontAwesomeIcon icon={faEdit} onClick={() => handleEditClick(user)} style={{ cursor: "pointer" }} className="edit-icon"/><span className="tooltip">Change Password</span></td>
                <td>
                  <button onClick={() => handleDeleteUser(user.user_id)} style={{ backgroundColor: "transparent", border: "none", cursor: "pointer", color:"black", position: "relative" }} className="delete-btn">
                  <FontAwesomeIcon icon={faTrash} />
                  <span className="tooltip">Delete</span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
 
      {editUser && (
        <div className="edit-form">
          <h3>ChangePassword</h3>
          <label>Role:</label>
          <input type="text" value={editUser.role} readOnly />

          <label>Code:</label>
          <input type="text" value={editUser.user_id} readOnly />

          <label>Username:</label>
          <input type="text" value={editUser.username} readOnly />

          <label>Email:</label>
<input 
  type="email" 
  value={editUser.email}
  readOnly
  // onChange={(e) => {
  //   const newEmail = e.target.value;
  //   setEditUser({ ...editUser, email: newEmail });
  // }} 
/>
{/* Show validation error if email is not valid */}
{editUser.email && !validateEmail(editUser.email) && (
  <p style={{ color: "red" }}>Invalid Email Format! Example: user@example.com</p>
)}
          <label>New Password:</label>
          <input 
  type="password"
  placeholder="Enter new password"  
  value={editUser.password} 
  onChange={(e) => {
    const newPassword = e.target.value;
    setEditUser({ ...editUser, password: newPassword });
  }} 
/>

{editUser.password && !validatePassword(editUser.password) && (
  <p style={{ color: "red" }}>Password must be 8 characters long, include uppercase, lowercase, number, and special character.</p>
)}
          <button 
  onClick={handleUpdateUser} 
  disabled={!validateEmail(editUser.email) || (editUser.password && !validatePassword(editUser.password))}
>
  Save&SendEmail
</button>
          <button onClick={() => setEditUser(null)}>Cancel</button>
        </div>
      )}
{/* table */}
<div className="table">
    <table border={1}>
      <tr>
        <th>Rsmcode</th>
        <th>Asmcode</th>
        <th>Storecode</th>
        <th>Action</th>

      </tr>
      <tr>
        <td>Rsm1</td>
        <td>asm1</td>
        <td>store1</td>
        <td>delete/edit</td>
      </tr>
      <tr>
        <td>Rsm1</td>
        <td>asm1</td>
        <td>store2</td>
        <td>delete/edit</td>

      </tr>
      <tr>
        <td>Rsm1</td>
        <td>asm2</td>
        <td>store3</td>
        <td>delete/edit</td>

      </tr>
      <tr>
        <td>Rsm1</td>
        <td>asm2</td>
        <td>store4</td>
        <td>delete/edit</td>

      </tr>
      <tr>
        <td>Rsm2</td>
        <td>asm3</td>
        <td>store5</td>
        <td>delete/edit</td>

      </tr>
      <tr>
        <td>Rsm2</td>
        <td>asm3</td>
        <td>store6</td>
        <td>delete/edit</td>

      </tr>
      <tr>
        <td>Rsm2</td>
        <td>asm4</td>
        <td>store7</td>
        <td>delete/edit</td>

      </tr>
      <tr>
        <td>Rsm2</td>
        <td>asm4</td>
        <td>store8</td>
        <td>delete/edit</td>

      </tr>
    </table>
    </div>
    <div className='upload'>
      <ul>
        <button><li>Upload</li></button>
        <button><li>Download</li></button>
       <button><li>ViewMapping</li></button> 
      </ul>
    </div>
    </>

  );
};




 

