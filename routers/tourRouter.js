const express = require("express");
const router = express.Router();
const requireAuth = require("../middleware/requireAuth");

const {
  getAllTours,
  getTourById,
  createTour,
  updateTour,
  deleteTour,
} = require("../controllers/tourControllers");
// const auth = require("../middleware/auth");

router.use(requireAuth);

router.get("/", getAllTours);
// router.use(auth);
router.post("/", createTour);
router.get("/:tourId", getTourById);
router.put("/:tourId", updateTour);
router.delete("/:tourId", deleteTour);

module.exports = router;

// const express = require("express");
// const router = express.Router();
// const requireAuth = require("../middleware/requireAuth");
// router.use(requireAuth);

// const {
//   getAllTours,
//   getTourById,
//   createTour,
//   updateTour,
//   deleteTour,
// } = require("../controllers/tourControllers");
// // const auth = require("../middleware/auth");

// router.get('/tours', requireAuth, getAllTours);
// // router.get("/", getAllTours);
// // router.use(auth);
// router.post("/", createTour);
// router.get("/:tourId", getTourById);
// router.put("/:tourId", updateTour);
// router.delete("/:tourId", deleteTour);

// module.exports = router;
